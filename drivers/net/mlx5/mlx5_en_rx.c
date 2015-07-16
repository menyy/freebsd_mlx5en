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

static inline int
mlx5e_alloc_rx_wqe(struct mlx5e_rq *rq,
    struct mlx5e_rx_wqe *wqe, u16 ix)
{
	struct mbuf *mb;
	dma_addr_t dma_addr;

	mb = m_getjcl(M_NOWAIT, MT_DATA, M_PKTHDR, rq->wqe_sz);
	if (unlikely(!mb))
		return (-ENOMEM);

	/* set initial mbuf length */
	mb->m_pkthdr.len = mb->m_len = rq->wqe_sz;

	dma_addr = dma_map_single(rq->pdev,
	    mb->m_data, mb->m_len, DMA_FROM_DEVICE);

	if (unlikely(dma_mapping_error(rq->pdev, dma_addr)))
		goto err_free_mbuf;

	/* get IP header aligned */
	m_adj(mb, MLX5E_NET_IP_ALIGN);

	MLX5E_RX_MBUF_DMA_ADDR(mb) = dma_addr;
	wqe->data.addr = cpu_to_be64(dma_addr + MLX5E_NET_IP_ALIGN);

	rq->mbuf[ix] = mb;

	return (0);

err_free_mbuf:
	m_freem(mb);
	return (-ENOMEM);
}

static void
mlx5e_post_rx_wqes(struct mlx5e_rq *rq)
{
	if (unlikely(rq->enabled == 0))
		return;

	while (!mlx5_wq_ll_is_full(&rq->wq)) {
		struct mlx5e_rx_wqe *wqe = mlx5_wq_ll_get_wqe(&rq->wq, rq->wq.head);

		if (unlikely(mlx5e_alloc_rx_wqe(rq, wqe, rq->wq.head)))
			break;

		mlx5_wq_ll_push(&rq->wq, be16_to_cpu(wqe->next.next_wqe_index));
	}

	/* ensure wqes are visible to device before updating doorbell record */
	wmb();

	mlx5_wq_ll_update_db_record(&rq->wq);
}

static inline void
mlx5e_build_rx_mbuf(struct mlx5_cqe64 *cqe,
    struct mlx5e_rq *rq, struct mbuf *mb)
{
	struct ifnet *ifp = rq->ifp;
	u32 cqe_bcnt = be32_to_cpu(cqe->byte_cnt);

	mb->m_pkthdr.len = mb->m_len = cqe_bcnt;
	mb->m_pkthdr.flowid = rq->ix;
	M_HASHTYPE_SET(mb, M_HASHTYPE_OPAQUE);
	mb->m_pkthdr.rcvif = ifp;

	if (likely(ifp->if_capabilities & IFCAP_RXCSUM) &&
	    ((cqe->hds_ip_ext & (CQE_L2_OK | CQE_L3_OK | CQE_L4_OK)) ==
	    (CQE_L2_OK | CQE_L3_OK | CQE_L4_OK))) {
		mb->m_pkthdr.csum_flags =
		    CSUM_IP_CHECKED | CSUM_IP_VALID |
		    CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
		mb->m_pkthdr.csum_data = htons(0xffff);
	} else {
		rq->stats.csum_none++;
	}

	if (cqe_has_vlan(cqe)) {
		mb->m_pkthdr.ether_vtag = be16_to_cpu(cqe->vlan_info);
		mb->m_flags |= M_VLANTAG;
	}
}

static void
mlx5e_poll_rx_cq(struct mlx5e_rq *rq, int budget)
{
#ifndef HAVE_TURBO_LRO
	struct lro_entry *queued;
#endif
	int i;

	for (i = 0; i < budget; i++) {
		struct mlx5e_rx_wqe *wqe;
		struct mlx5_cqe64 *cqe;
		struct mbuf *mb;
		__be16 wqe_counter_be;
		u16 wqe_counter;

		cqe = mlx5e_get_cqe(&rq->cq);
		if (!cqe)
			break;

		wqe_counter_be = cqe->wqe_counter;
		wqe_counter = be16_to_cpu(wqe_counter_be);
		wqe = mlx5_wq_ll_get_wqe(&rq->wq, wqe_counter);
		mb = rq->mbuf[wqe_counter];
		rq->mbuf[wqe_counter] = NULL;

		dma_unmap_single(rq->pdev,
		    MLX5E_RX_MBUF_DMA_ADDR(mb),
		    mb->m_len + MLX5E_NET_IP_ALIGN,
		    DMA_FROM_DEVICE);

		if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
			rq->stats.wqe_err++;
			m_freem(mb);
			goto wq_ll_pop;
		}
		mlx5e_build_rx_mbuf(cqe, rq, mb);
		rq->stats.packets++;
#ifdef HAVE_TURBO_LRO
		if (mb->m_pkthdr.csum_flags == 0 ||
		    (rq->ifp->if_capenable & IFCAP_LRO) == 0 ||
		    rq->lro.mbuf == NULL) {
			/* normal input */
			rq->ifp->if_input(rq->ifp, mb);
		} else {
			tcp_tlro_rx(&rq->lro, mb);
		}
#else
		if (mb->m_pkthdr.csum_flags == 0 ||
		    (rq->ifp->if_capenable & IFCAP_LRO) == 0 ||
		    rq->lro.lro_cnt == 0 ||
		    tcp_lro_rx(&rq->lro, mb, 0) != 0) {
			rq->ifp->if_input(rq->ifp, mb);
		}
#endif
wq_ll_pop:
		mlx5_wq_ll_pop(&rq->wq, wqe_counter_be,
		    &wqe->next.next_wqe_index);
	}

	mlx5_cqwq_update_db_record(&rq->cq.wq);

	/* ensure cq space is freed before enabling more cqes */
	wmb();
#ifndef HAVE_TURBO_LRO
	while ((queued = SLIST_FIRST(&rq->lro.lro_active)) != NULL) {
		SLIST_REMOVE_HEAD(&rq->lro.lro_active, next);
		tcp_lro_flush(&rq->lro, queued);
	}
#endif
}

void
mlx5e_rx_cq_function(struct mlx5e_cq *cq)
{
	struct mlx5e_rq *rq = container_of(cq, struct mlx5e_rq, cq);

	mtx_lock(&rq->mtx);
	mlx5e_poll_rx_cq(rq, MLX5E_BUDGET_MAX);
	mlx5e_post_rx_wqes(rq);
	mlx5e_cq_arm(cq);
#ifdef HAVE_TURBO_LRO
	tcp_tlro_flush(&rq->lro, 1);
#endif
	mtx_unlock(&rq->mtx);
}
