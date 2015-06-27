/*-
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "en.h"

void
mlx5e_send_nop(struct mlx5e_sq *sq, bool notify_hw)
{
	u16 pi = sq->pc & sq->wq.sz_m1;
	struct mlx5e_tx_wqe *wqe = mlx5_wq_cyc_get_wqe(&sq->wq, pi);

	memset(&wqe->ctrl, 0, sizeof(wqe->ctrl));

	wqe->ctrl.opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | MLX5_OPCODE_NOP);
	wqe->ctrl.qpn_ds = cpu_to_be32((sq->sqn << 8) | 0x01);
	wqe->ctrl.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;

	sq->mbuf[pi] = NULL;
	sq->pc++;
	if (notify_hw)
		mlx5e_tx_notify_hw(sq, wqe, 0);
}

static void
mlx5e_dma_pop_last_pushed(struct mlx5e_sq *sq, dma_addr_t *addr,
    u32 * size)
{
	sq->dma_fifo_pc--;
	*addr = sq->dma_fifo[sq->dma_fifo_pc & sq->dma_fifo_mask].addr;
	*size = sq->dma_fifo[sq->dma_fifo_pc & sq->dma_fifo_mask].size;
}

static void
mlx5e_dma_unmap_wqe_err(struct mlx5e_sq *sq, struct mbuf *mb)
{
	dma_addr_t addr;
	u32 size;
	int i;

	for (i = 0; i < MLX5E_TX_MBUF_CB(mb)->num_dma; i++) {
		mlx5e_dma_pop_last_pushed(sq, &addr, &size);
		dma_unmap_single(sq->pdev, addr, size, DMA_TO_DEVICE);
	}
}

static inline void
mlx5e_dma_push(struct mlx5e_sq *sq, dma_addr_t addr,
    u32 size)
{
	sq->dma_fifo[sq->dma_fifo_pc & sq->dma_fifo_mask].addr = addr;
	sq->dma_fifo[sq->dma_fifo_pc & sq->dma_fifo_mask].size = size;
	sq->dma_fifo_pc++;
}

static inline void
mlx5e_dma_get(struct mlx5e_sq *sq, u32 i, dma_addr_t *addr,
    u32 * size)
{
	*addr = sq->dma_fifo[i & sq->dma_fifo_mask].addr;
	*size = sq->dma_fifo[i & sq->dma_fifo_mask].size;
}

static uint32_t mlx5e_hash_value;
static void
mlx5e_hash_init(void *arg)
{
	mlx5e_hash_value = m_ether_tcpip_hash_init();
}

SYSINIT(mlx5e_hash_init, SI_SUB_KLD, SI_ORDER_SECOND, &mlx5e_hash_init, NULL);

static struct mlx5e_sq *
mlx5e_select_queue(struct net_device *dev, struct mbuf *mb)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	u32 ch;
	u32 tc;

	/* check if channels are successfully opened */
	if (priv->channel == NULL)
		return (NULL);

	/* obtain VLAN information if present */
	if (mb->m_flags & M_VLANTAG) {
		tc = (mb->m_pkthdr.ether_vtag >> 13);
		if (tc >= priv->num_tc)
			tc = priv->default_vlan_prio;
	} else {
		tc = priv->default_vlan_prio;
	}

	ch = priv->params.num_channels;

	/* check if flowid is set */
	if (M_HASHTYPE_GET(mb) != M_HASHTYPE_NONE) {
		ch = mb->m_pkthdr.flowid % ch;
	} else {
		ch = m_ether_tcpip_hash(MBUF_HASHFLAG_L3 |
		    MBUF_HASHFLAG_L4, mb, mlx5e_hash_value) % ch;
	}

	/* check if channel is allocated */
	if (priv->channel[ch] == NULL)
		return (NULL);

	return (&priv->channel[ch]->sq[tc]);
}

static inline u16
mlx5e_get_inline_hdr_size(struct mlx5e_sq *sq, struct mbuf *mb)
{
	return (MIN(MLX5E_MAX_TX_INLINE, mb->m_len));
}

static inline void
mlx5e_insert_vlan(void *start, struct mbuf *mb, u16 ihs)
{
	struct ether_vlan_header *vhdr = start;
	const int size = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;

	m_copydata(mb, 0, size, (void *)vhdr);
	m_adj(mb, size);
}

static int
mlx5e_get_header_size(struct mbuf *mb)
{
	struct ether_vlan_header *eh;
	struct tcphdr *th;
	struct ip *ip;
	int ip_hlen, tcp_hlen;
	struct ip6_hdr *ip6;
	uint16_t eth_type;
	int eth_hdr_len;

	eh = mtod(mb, struct ether_vlan_header *);
	if (mb->m_len < ETHER_HDR_LEN)
		return (0);
	if (eh->evl_encap_proto == htons(ETHERTYPE_VLAN)) {
		eth_type = ntohs(eh->evl_proto);
		eth_hdr_len = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
	} else {
		eth_type = ntohs(eh->evl_encap_proto);
		eth_hdr_len = ETHER_HDR_LEN;
	}
	if (mb->m_len < eth_hdr_len)
		return (0);
	switch (eth_type) {
	case ETHERTYPE_IP:
		ip = (struct ip *)(mb->m_data + eth_hdr_len);
		if (mb->m_len < eth_hdr_len + sizeof(*ip))
			return (0);
		if (ip->ip_p != IPPROTO_TCP)
			return (0);
		ip_hlen = ip->ip_hl << 2;
		eth_hdr_len += ip_hlen;
		break;
	case ETHERTYPE_IPV6:
		ip6 = (struct ip6_hdr *)(mb->m_data + eth_hdr_len);
		if (mb->m_len < eth_hdr_len + sizeof(*ip6))
			return (0);
		if (ip6->ip6_nxt != IPPROTO_TCP)
			return (0);
		eth_hdr_len += sizeof(*ip6);
		break;
	default:
		return (0);
	}
	if (mb->m_len < eth_hdr_len + sizeof(*th))
		return (0);
	th = (struct tcphdr *)(mb->m_data + eth_hdr_len);
	tcp_hlen = th->th_off << 2;
	eth_hdr_len += tcp_hlen;
	if (mb->m_len < eth_hdr_len)
		return (0);
	return (eth_hdr_len);
}

static u32
mlx5e_num_frags(struct mbuf *mb)
{
	u32 frags = 0;
	do {
		if (mb->m_len != 0)
			frags++;
	} while ((mb = mb->m_next) != NULL);
	return (frags);
}

static int
mlx5e_sq_xmit(struct mlx5e_sq *sq, struct mbuf *mb)
{
	struct mlx5_wqe_data_seg *dseg;
	struct net_device *netdev;
	struct mlx5e_tx_wqe *wqe;
	struct mbuf *mx;
	u16 ds_cnt;
	u16 ihs;
	u16 pi;
	u8 opcode;

	/* check if queue is full */
	if (unlikely(!mlx5e_sq_has_room_for(sq, 2 * MLX5_SEND_WQE_MAX_WQEBBS))) {
		sq->stats.dropped++;
		m_freem(mb);
		return (ENOBUFS);
	}

	/* align SQ edge with NOPs to avoid WQE wrap around */
	while (((~sq->pc) & sq->wq.sz_m1) < (MLX5_SEND_WQE_MAX_WQEBBS - 1))
		mlx5e_send_nop(sq, false);

	/* setup local variables */
	pi = sq->pc & sq->wq.sz_m1;
	wqe = mlx5_wq_cyc_get_wqe(&sq->wq, pi);
	netdev = sq->channel->netdev;

	memset(wqe, 0, sizeof(*wqe));

	/*
	 * Check that the number of fragments in the chain doesn't
	 * exceed the maximum:
	 */
	if (mlx5e_num_frags(mb) > MLX5E_MAX_TX_MBUF_FRAGS) {
		mx = m_defrag(mb, M_NOWAIT);
		if (mx == NULL) {
			sq->stats.dropped++;
			m_freem(mb);
			return (ENOMEM);
		} else {
			if (mlx5e_num_frags(mx) > MLX5E_MAX_TX_MBUF_FRAGS) {
				sq->stats.dropped++;
				m_freem(mx);
				return (ENOMEM);
			}
			mb = mx;
		}
	}

	/* send a copy of the frame to the BPF listener, if any */
	if (netdev != NULL && netdev->if_bpf != NULL)
		ETHER_BPF_MTAP(netdev, mb);

	if (mb->m_pkthdr.csum_flags & (CSUM_IP | CSUM_TSO |
	    CSUM_TCP | CSUM_UDP | CSUM_TCP_IPV6 | CSUM_UDP_IPV6)) {
		wqe->eth.cs_flags = MLX5_ETH_WQE_L3_CSUM | MLX5_ETH_WQE_L4_CSUM;
	} else {
		sq->stats.csum_offload_none++;
	}

	if (mb->m_pkthdr.csum_flags & CSUM_TSO) {
		u32 payload_len;
		u32 mss = mb->m_pkthdr.tso_segsz;
		u32 num_pkts;

		wqe->eth.mss = cpu_to_be16(mss);
		opcode = MLX5_OPCODE_LSO;
		ihs = mlx5e_get_header_size(mb);
		payload_len = mb->m_pkthdr.len - ihs;
		if (payload_len == 0)
			num_pkts = 1;
		else
			num_pkts = DIV_ROUND_UP(payload_len, mss);
		MLX5E_TX_MBUF_CB(mb)->num_bytes =
		    payload_len + (num_pkts * ihs);

		sq->stats.tso_packets++;
		sq->stats.tso_bytes += payload_len;
	} else {
		opcode = MLX5_OPCODE_SEND;
		ihs = mlx5e_get_inline_hdr_size(sq, mb);
		MLX5E_TX_MBUF_CB(mb)->num_bytes =
		    max_t (unsigned int, mb->m_pkthdr.len,
		    ETHER_MIN_LEN - ETHER_CRC_LEN);
	}
	if (mb->m_flags & M_VLANTAG) {
		mlx5e_insert_vlan(wqe->eth.inline_hdr_start, mb, ihs);
	} else {
		m_copydata(mb, 0, ihs, wqe->eth.inline_hdr_start);
		m_adj(mb, ihs);
	}

	wqe->eth.inline_hdr_sz = cpu_to_be16(ihs);

	ds_cnt = sizeof(*wqe) / MLX5_SEND_WQE_DS;
	if (likely(ihs > sizeof(wqe->eth.inline_hdr_start))) {
		ds_cnt += DIV_ROUND_UP(ihs - sizeof(wqe->eth.inline_hdr_start),
		    MLX5_SEND_WQE_DS);
	}
	dseg = ((struct mlx5_wqe_data_seg *)&wqe->ctrl) + ds_cnt;

	for (mx = mb; mx != NULL; mx = mx->m_next) {
		dma_addr_t dma_addr;

		if (mx->m_len == 0)
			continue;

		dma_addr = dma_map_single(sq->pdev, mx->m_data, mx->m_len,
		    DMA_TO_DEVICE);
		if (unlikely(dma_mapping_error(sq->pdev, dma_addr)))
			goto dma_unmap_wqe_err;

		dseg->addr = cpu_to_be64(dma_addr);
		dseg->lkey = sq->mkey_be;
		dseg->byte_count = cpu_to_be32(mx->m_len);

		mlx5e_dma_push(sq, dma_addr, mx->m_len);
		dseg++;
	}

	MLX5E_TX_MBUF_CB(mb)->num_dma =
	    (dseg - ((struct mlx5_wqe_data_seg *)&wqe->ctrl)) - ds_cnt;
	ds_cnt += MLX5E_TX_MBUF_CB(mb)->num_dma;

	wqe->ctrl.opmod_idx_opcode = cpu_to_be32((sq->pc << 8) | opcode);
	wqe->ctrl.qpn_ds = cpu_to_be32((sq->sqn << 8) | ds_cnt);
	wqe->ctrl.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;

	sq->mbuf[pi] = mb;

	MLX5E_TX_MBUF_CB(mb)->num_wqebbs = DIV_ROUND_UP(ds_cnt,
	    MLX5_SEND_WQEBB_NUM_DS);
	sq->pc += MLX5E_TX_MBUF_CB(mb)->num_wqebbs;

	mlx5e_tx_notify_hw(sq, wqe, 0);

	sq->stats.packets++;
	return (0);

dma_unmap_wqe_err:
	sq->stats.dropped++;
	mlx5e_dma_unmap_wqe_err(sq, mb);
	m_freem(mb);
	return (ENXIO);
}

static void
mlx5e_poll_tx_cq(struct mlx5e_sq *sq, int budget)
{
	u32 dma_fifo_cc;
	u32 nbytes;
	u16 npkts;
	u16 sqcc;

	npkts = 0;
	nbytes = 0;

	/*
	 * sq->cc must be updated only after mlx5_cqwq_update_db_record(),
	 * otherwise a cq overrun may occur
	 */
	sqcc = sq->cc;

	/* avoid dirtying sq cache line every cqe */
	dma_fifo_cc = sq->dma_fifo_cc;

	while (budget--) {
		struct mlx5_cqe64 *cqe;
		struct mbuf *mb;
		u16 ci;
		int j;

		cqe = mlx5e_get_cqe(&sq->cq);
		if (!cqe)
			break;

		ci = sqcc & sq->wq.sz_m1;
		mb = sq->mbuf[ci];
		sq->mbuf[ci] = NULL;	/* clear mbuf pointer */

		if (unlikely(mb == NULL)) {
			/* nop */
			sq->stats.nop++;
			sqcc++;
			continue;
		}
		for (j = 0; j < MLX5E_TX_MBUF_CB(mb)->num_dma; j++) {
			dma_addr_t addr;
			u32 size;

			mlx5e_dma_get(sq, dma_fifo_cc, &addr, &size);
			dma_fifo_cc++;
			dma_unmap_single(sq->pdev, addr, size, DMA_TO_DEVICE);
		}

		npkts++;
		nbytes += MLX5E_TX_MBUF_CB(mb)->num_bytes;
		sqcc += MLX5E_TX_MBUF_CB(mb)->num_wqebbs;

		/* free transmitted mbuf */
		m_freem(mb);
	}

	mlx5_cqwq_update_db_record(&sq->cq.wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();

	sq->dma_fifo_cc = dma_fifo_cc;
	sq->cc = sqcc;
}

int
mlx5e_xmit(struct net_device *dev, struct mbuf *mb)
{
	struct mlx5e_sq *sq;
	int ret;

	sq = mlx5e_select_queue(dev, mb);
	if (sq == NULL) {
		/* invalid send queue */
		m_freem(mb);
		return (ENXIO);
	}
	spin_lock(&sq->lock);
	mlx5e_poll_tx_cq(sq, MLX5E_BUDGET_MAX);
	ret = mlx5e_sq_xmit(sq, mb);
	spin_unlock(&sq->lock);
	return (ret);
}

void
mlx5e_tx_cq_function(struct mlx5e_cq *cq)
{
	struct mlx5e_sq *sq = container_of(cq, struct mlx5e_sq, cq);

	spin_lock(&sq->lock);
	mlx5e_poll_tx_cq(sq, MLX5E_BUDGET_MAX);
	mlx5e_cq_arm(cq);
	spin_unlock(&sq->lock);
}
