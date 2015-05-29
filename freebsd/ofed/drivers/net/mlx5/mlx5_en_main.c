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

#include <sys/sockio.h>

struct mlx5e_rq_param {
	u32	rqc [MLX5_ST_SZ_DW(rqc)];
	struct mlx5_wq_param wq;
};

struct mlx5e_sq_param {
	u32	sqc [MLX5_ST_SZ_DW(sqc)];
	struct mlx5_wq_param wq;
};

struct mlx5e_cq_param {
	u32	cqc [MLX5_ST_SZ_DW(cqc)];
	struct mlx5_wq_param wq;
	u16	eq_ix;
};

struct mlx5e_channel_param {
	struct mlx5e_rq_param rq;
	struct mlx5e_sq_param sq;
	struct mlx5e_cq_param rx_cq;
	struct mlx5e_cq_param tx_cq;
};

static const struct {
	u32	subtype;
	u64	baudrate;
}	mlx5e_mode_table[MLX5E_LINK_MODES_NUMBER] = {

	[MLX5E_1000BASE_CX_SGMII] = {
		.subtype = IFM_1000_CX_SGMII,
		.baudrate = IF_Mbps(1000ULL),
	},
	[MLX5E_1000BASE_KX] = {
		.subtype = IFM_1000_KX,
		.baudrate = IF_Mbps(1000ULL),
	},
	[MLX5E_10GBASE_CX4] = {
		.subtype = IFM_10G_CX4,
		.baudrate = IF_Gbps(10ULL),
	},
	[MLX5E_10GBASE_KX4] = {
		.subtype = IFM_10G_KX4,
		.baudrate = IF_Gbps(10ULL),
	},
	[MLX5E_10GBASE_KR] = {
		.subtype = IFM_10G_KR,
		.baudrate = IF_Gbps(10ULL),
	},
	[MLX5E_20GBASE_KR2] = {
		.subtype = IFM_20G_KR2,
		.baudrate = IF_Gbps(20ULL),
	},
	[MLX5E_40GBASE_CR4] = {
		.subtype = IFM_40G_CR4,
		.baudrate = IF_Gbps(40ULL),
	},
	[MLX5E_40GBASE_KR4] = {
		.subtype = IFM_40G_KR4,
		.baudrate = IF_Gbps(40ULL),
	},
	[MLX5E_56GBASE_R4] = {
		.subtype = IFM_56G_R4,
		.baudrate = IF_Gbps(56ULL),
	},
	[MLX5E_10GBASE_CR] = {
		.subtype = IFM_10G_CR1,
		.baudrate = IF_Gbps(10ULL),
	},
	[MLX5E_10GBASE_SR] = {
		.subtype = IFM_10G_SR,
		.baudrate = IF_Gbps(10ULL),
	},
	[MLX5E_10GBASE_ER] = {
		.subtype = IFM_10G_ER,
		.baudrate = IF_Gbps(10ULL),
	},
	[MLX5E_40GBASE_SR4] = {
		.subtype = IFM_40G_SR4,
		.baudrate = IF_Gbps(40ULL),
	},
	[MLX5E_40GBASE_LR4] = {
		.subtype = IFM_40G_LR4,
		.baudrate = IF_Gbps(40ULL),
	},
	[MLX5E_100GBASE_CR4] = {
		.subtype = IFM_100G_CR4,
		.baudrate = IF_Gbps(100ULL),
	},
	[MLX5E_100GBASE_SR4] = {
		.subtype = IFM_100G_SR4,
		.baudrate = IF_Gbps(100ULL),
	},
	[MLX5E_100GBASE_KR4] = {
		.subtype = IFM_100G_KR4,
		.baudrate = IF_Gbps(100ULL),
	},
	[MLX5E_100GBASE_LR4] = {
		.subtype = IFM_100G_LR4,
		.baudrate = IF_Gbps(100ULL),
	},
	[MLX5E_100BASE_TX] = {
		.subtype = IFM_100_TX,
		.baudrate = IF_Mbps(100ULL),
	},
	[MLX5E_100BASE_T] = {
		.subtype = IFM_100_T,
		.baudrate = IF_Mbps(100ULL),
	},
	[MLX5E_10GBASE_T] = {
		.subtype = IFM_10G_T,
		.baudrate = IF_Gbps(10ULL),
	},
	[MLX5E_25GBASE_CR] = {
		.subtype = IFM_25G_CR,
		.baudrate = IF_Gbps(25ULL),
	},
	[MLX5E_25GBASE_KR] = {
		.subtype = IFM_25G_KR,
		.baudrate = IF_Gbps(25ULL),
	},
	[MLX5E_25GBASE_SR] = {
		.subtype = IFM_25G_SR,
		.baudrate = IF_Gbps(25ULL),
	},
	[MLX5E_50GBASE_CR2] = {
		.subtype = IFM_50G_CR2,
		.baudrate = IF_Gbps(50ULL),
	},
	[MLX5E_50GBASE_KR2] = {
		.subtype = IFM_50G_KR2,
		.baudrate = IF_Gbps(50ULL),
	},
};

static void
mlx5e_update_carrier(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	u32 eth_proto_oper;
	int error;
	u8 port_state;
	u8 i;

	port_state = mlx5_query_vport_state(mdev,
	    MLX5_QUERY_VPORT_STATE_IN_OP_MOD_VNIC_VPORT);

	if (port_state == VPORT_STATE_UP) {
		priv->media_status_last |= IFM_ACTIVE;
		if_link_state_change(priv->netdev, LINK_STATE_UP);
	} else {
		priv->media_status_last &= ~IFM_ACTIVE;
		priv->media_active_last = IFM_ETHER;
		if_link_state_change(priv->netdev, LINK_STATE_DOWN);
		return;
	}

	error = mlx5_query_port_ptys(mdev, out, sizeof(out), MLX5_PTYS_EN);
	if (error) {
		priv->media_active_last = IFM_ETHER;
		priv->netdev->if_baudrate = 1;
		netdev_err(priv->netdev, "%s: query port ptys failed: 0x%x\n",
		    __func__, error);
		return;
	}
	eth_proto_oper = MLX5_GET(ptys_reg, out, eth_proto_oper);

	for (i = 0; i != MLX5E_LINK_MODES_NUMBER; i++) {
		if (mlx5e_mode_table[i].baudrate == 0)
			continue;
		if (MLX5E_PROT_MASK(i) & eth_proto_oper) {
			priv->netdev->if_baudrate =
			    mlx5e_mode_table[i].baudrate;
			priv->media_active_last =
			    mlx5e_mode_table[i].subtype | IFM_ETHER |
			    IFM_FDX | priv->media_active_user;
		}
	}
}

static void
mlx5e_media_status(struct ifnet *dev, struct ifmediareq *ifmr)
{
	struct mlx5e_priv *priv = dev->if_softc;

	ifmr->ifm_status = priv->media_status_last;
	ifmr->ifm_active = priv->media_active_last;
}

static int
mlx5e_media_change(struct ifnet *dev)
{
	struct mlx5e_priv *priv = dev->if_softc;

	if (IFM_TYPE(priv->media.ifm_media) != IFM_ETHER)
		return (EINVAL);
	switch (IFM_SUBTYPE(priv->media.ifm_media)) {
	case IFM_AUTO:
		break;
	default:
		if (IFM_SUBTYPE(priv->media.ifm_media) !=
		    IFM_SUBTYPE(priv->media_active_last) ||
		    (priv->media.ifm_media & IFM_FDX) == 0) {
			/* We only support autoselect */
			return (EINVAL);
		}
		break;
	}

	/* Allow user to set/clear pause */
	priv->media_active_user =
	    IFM_OPTIONS(priv->media.ifm_media) &
	    (IFM_ETH_RXPAUSE | IFM_ETH_TXPAUSE);

	return (0);
}

static void
mlx5e_update_carrier_work(struct work_struct *work)
{
	struct mlx5e_priv *priv = container_of(work, struct mlx5e_priv,
	    update_carrier_work);

	mutex_lock(&priv->state_lock);
	if (test_bit(MLX5E_STATE_OPENED, &priv->state))
		mlx5e_update_carrier(priv);
	mutex_unlock(&priv->state_lock);
}

static void
mlx5e_update_pport_counters(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_pport_stats *s = &priv->stats.pport;
	u32 *in;
	u32 *out;
	u64 *ptr;
	unsigned sz = MLX5_ST_SZ_BYTES(ppcnt_reg);
	unsigned x;
	unsigned y;

	in  = mlx5_vzalloc(sz);
	out = mlx5_vzalloc(sz);
	if (in == NULL || out == NULL)
		goto free_out;

	ptr = (uint64_t *)MLX5_ADDR_OF(ppcnt_reg, out, counter_set);

	MLX5_SET(ppcnt_reg, in, local_port, 1);

	MLX5_SET(ppcnt_reg, in, grp, MLX5_IEEE_802_3_COUNTERS_GROUP);
	mlx5_core_access_reg(mdev, in, sz, out, sz, MLX5_REG_PPCNT, 0, 0);
	for (x = y = 0; x != MLX5E_PPORT_IEEE802_3_STATS_NUM; x++, y++)
		s->arg[y] = be64toh(ptr[x]);

	MLX5_SET(ppcnt_reg, in, grp, MLX5_RFC_2863_COUNTERS_GROUP);
	mlx5_core_access_reg(mdev, in, sz, out, sz, MLX5_REG_PPCNT, 0, 0);
	for (x = 0; x != MLX5E_PPORT_RFC2863_STATS_NUM; x++, y++)
		s->arg[y] = be64toh(ptr[x]);

	MLX5_SET(ppcnt_reg, in, grp, MLX5_RFC_2819_COUNTERS_GROUP);
	mlx5_core_access_reg(mdev, in, sz, out, sz, MLX5_REG_PPCNT, 0, 0);
	for (x = 0; x != MLX5E_PPORT_RFC2819_STATS_NUM; x++, y++)
		s->arg[y] = be64toh(ptr[x]);
free_out:
	kvfree(in);
	kvfree(out);
}

static void
mlx5e_update_stats_work(struct work_struct *work)
{
	struct mlx5e_priv *priv = container_of(work, struct mlx5e_priv,
	    update_stats_work);
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_vport_stats *s = &priv->stats.vport;
	struct mlx5e_rq_stats *rq_stats;
	struct mlx5e_sq_stats *sq_stats;
	u32 in[MLX5_ST_SZ_DW(query_vport_counter_in)];
	u32 *out;
	int outlen = MLX5_ST_SZ_BYTES(query_vport_counter_out);
	u64 tx_offload_none;
	int i, j;

	mutex_lock(&priv->state_lock);
	out = mlx5_vzalloc(outlen);
	if (out == NULL)
		goto free_out;
	if (test_bit(MLX5E_STATE_OPENED, &priv->state) == 0)
		goto free_out;

	/* Collect firts the SW counters and then HW for consistency */
	s->tso_packets = 0;
	s->tso_bytes = 0;
	s->tx_queue_stopped = 0;
	s->tx_queue_wake = 0;
	s->tx_queue_dropped = 0;
	tx_offload_none = 0;
	s->lro_packets = 0;
	s->lro_bytes = 0;
	s->rx_csum_none = 0;
	s->rx_wqe_err = 0;
	for (i = 0; i < priv->params.num_channels; i++) {
		rq_stats = &priv->channel[i]->rq.stats;

		s->lro_packets += rq_stats->lro_packets;
		s->lro_bytes += rq_stats->lro_bytes;
		s->rx_csum_none += rq_stats->csum_none;
		s->rx_wqe_err += rq_stats->wqe_err;

		for (j = 0; j < priv->num_tc; j++) {
			sq_stats = &priv->channel[i]->sq[j].stats;

			s->tso_packets += sq_stats->tso_packets;
			s->tso_bytes += sq_stats->tso_bytes;
			s->tx_queue_stopped += sq_stats->stopped;
			s->tx_queue_wake += sq_stats->wake;
			s->tx_queue_dropped += sq_stats->dropped;
			tx_offload_none += sq_stats->csum_offload_none;
		}
	}

	/* HW counters */
	memset(in, 0, sizeof(in));

	MLX5_SET(query_vport_counter_in, in, opcode,
	    MLX5_CMD_OP_QUERY_VPORT_COUNTER);
	MLX5_SET(query_vport_counter_in, in, op_mod, 0);
	MLX5_SET(query_vport_counter_in, in, other_vport, 0);

	memset(out, 0, outlen);

	if (mlx5_cmd_exec(mdev, in, sizeof(in), out, outlen))
		goto free_out;

#define	MLX5_GET_CTR(out, x) \
	MLX5_GET64(query_vport_counter_out, out, x)

	s->rx_error_packets =
	    MLX5_GET_CTR(out, received_errors.packets);
	s->rx_error_bytes =
	    MLX5_GET_CTR(out, received_errors.octets);
	s->tx_error_packets =
	    MLX5_GET_CTR(out, transmit_errors.packets);
	s->tx_error_bytes =
	    MLX5_GET_CTR(out, transmit_errors.octets);

	s->rx_unicast_packets =
	    MLX5_GET_CTR(out, received_eth_unicast.packets);
	s->rx_unicast_bytes =
	    MLX5_GET_CTR(out, received_eth_unicast.octets);
	s->tx_unicast_packets =
	    MLX5_GET_CTR(out, transmitted_eth_unicast.packets);
	s->tx_unicast_bytes =
	    MLX5_GET_CTR(out, transmitted_eth_unicast.octets);

	s->rx_multicast_packets =
	    MLX5_GET_CTR(out, received_eth_multicast.packets);
	s->rx_multicast_bytes =
	    MLX5_GET_CTR(out, received_eth_multicast.octets);
	s->tx_multicast_packets =
	    MLX5_GET_CTR(out, transmitted_eth_multicast.packets);
	s->tx_multicast_bytes =
	    MLX5_GET_CTR(out, transmitted_eth_multicast.octets);

	s->rx_broadcast_packets =
	    MLX5_GET_CTR(out, received_eth_broadcast.packets);
	s->rx_broadcast_bytes =
	    MLX5_GET_CTR(out, received_eth_broadcast.octets);
	s->tx_broadcast_packets =
	    MLX5_GET_CTR(out, transmitted_eth_broadcast.packets);
	s->tx_broadcast_bytes =
	    MLX5_GET_CTR(out, transmitted_eth_broadcast.octets);

	s->rx_packets =
	    s->rx_unicast_packets +
	    s->rx_multicast_packets +
	    s->rx_broadcast_packets;
	s->rx_bytes =
	    s->rx_unicast_bytes +
	    s->rx_multicast_bytes +
	    s->rx_broadcast_bytes;
	s->tx_packets =
	    s->tx_unicast_packets +
	    s->tx_multicast_packets +
	    s->tx_broadcast_packets;
	s->tx_bytes =
	    s->tx_unicast_bytes +
	    s->tx_multicast_bytes +
	    s->tx_broadcast_bytes;

	/* Update calculated offload counters */
	s->tx_csum_offload = s->tx_packets - tx_offload_none;
	s->rx_csum_good = s->rx_packets - s->rx_csum_none;

	/* Update per port counters */
	mlx5e_update_pport_counters(priv);
free_out:
	kvfree(out);
	mutex_unlock(&priv->state_lock);
}

static void
mlx5e_update_stats(unsigned long data)
{
	struct mlx5e_priv *priv = (struct mlx5e_priv *)data;

	schedule_work(&priv->update_stats_work);

	mod_timer(&priv->watchdog, jiffies + HZ);
}

static void
mlx5e_async_event_sub(struct mlx5e_priv *priv,
    enum mlx5_dev_event event)
{
	switch (event) {
	case MLX5_DEV_EVENT_PORT_UP:
	case MLX5_DEV_EVENT_PORT_DOWN:
		schedule_work(&priv->update_carrier_work);
		break;

	default:
		break;
	}
}

static void
mlx5e_async_event(struct mlx5_core_dev *mdev, void *vpriv,
    enum mlx5_dev_event event, unsigned long param)
{
	struct mlx5e_priv *priv = vpriv;

	spin_lock(&priv->async_events_spinlock);
	if (test_bit(MLX5E_STATE_ASYNC_EVENTS_ENABLE, &priv->state))
		mlx5e_async_event_sub(priv, event);
	spin_unlock(&priv->async_events_spinlock);
}

static void
mlx5e_enable_async_events(struct mlx5e_priv *priv)
{
	set_bit(MLX5E_STATE_ASYNC_EVENTS_ENABLE, &priv->state);
}

static void
mlx5e_disable_async_events(struct mlx5e_priv *priv)
{
	spin_lock_irq(&priv->async_events_spinlock);
	clear_bit(MLX5E_STATE_ASYNC_EVENTS_ENABLE, &priv->state);
	spin_unlock_irq(&priv->async_events_spinlock);
}

static const char *mlx5e_rq_stats_desc[] = {
	MLX5E_RQ_STATS(MLX5E_STATS_DESC)
};

static int
mlx5e_create_rq(struct mlx5e_channel *c,
    struct mlx5e_rq_param *param,
    struct mlx5e_rq *rq)
{
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	char buffer[16];
	void *rqc = param->rqc;
	void *rqc_wq = MLX5_ADDR_OF(rqc, rqc, wq);
	int wq_sz;
	int err;
	int i;

	err = mlx5_wq_ll_create(mdev, &param->wq, rqc_wq, &rq->wq,
	    &rq->wq_ctrl);
	if (err)
		return (err);

	rq->wq.db = &rq->wq.db[MLX5_RCV_DBR];

	rq->wqe_sz = priv->netdev->if_mtu + MLX5E_MTU_OVERHEAD;
	if (rq->wqe_sz > MJUM16BYTES) {
		err = -ENOMEM;
		goto err_rq_wq_destroy;
	} else if (rq->wqe_sz > MJUM9BYTES) {
		rq->wqe_sz = MJUM16BYTES;
	} else if (rq->wqe_sz > MJUMPAGESIZE) {
		rq->wqe_sz = MJUM9BYTES;
	} else if (rq->wqe_sz > MCLBYTES) {
		rq->wqe_sz = MJUMPAGESIZE;
	} else {
		rq->wqe_sz = MCLBYTES;
	}

	wq_sz = mlx5_wq_ll_get_size(&rq->wq);
	rq->mbuf = kzalloc(wq_sz * sizeof(rq->mbuf[0]), GFP_KERNEL);
	if (rq->mbuf == NULL) {
		err = -ENOMEM;
		goto err_rq_wq_destroy;
	}

	for (i = 0; i < wq_sz; i++) {
		struct mlx5e_rx_wqe *wqe = mlx5_wq_ll_get_wqe(&rq->wq, i);
		uint32_t byte_count = rq->wqe_sz - MLX5E_NET_IP_ALIGN;

		wqe->data.lkey = c->mkey_be;
		wqe->data.byte_count = cpu_to_be32(byte_count | MLX5_HW_START_PADDING);
	}

	rq->pdev = c->pdev;
	rq->netdev = c->netdev;
	rq->channel = c;
	rq->ix = c->ix;

	snprintf(buffer, sizeof(buffer), "rxstat%d", c->ix);
	mlx5e_create_stats(&rq->stats.ctx, SYSCTL_CHILDREN(priv->sysctl),
	    buffer, mlx5e_rq_stats_desc, MLX5E_RQ_STATS_NUM,
	    rq->stats.arg);

#ifdef HAVE_TURBO_LRO
	if (tcp_tlro_init(&rq->lro, c->netdev, MLX5E_BUDGET_MAX) != 0)
		rq->lro.mbuf = NULL;
#else
	if (tcp_lro_init(&rq->lro))
		rq->lro.lro_cnt = 0;
	else
		rq->lro.ifp = c->netdev;
#endif

	return (0);

err_rq_wq_destroy:
	mlx5_wq_destroy(&rq->wq_ctrl);

	return (err);
}

static void
mlx5e_destroy_rq(struct mlx5e_rq *rq)
{
	/* destroy all sysctl nodes */
	sysctl_ctx_free(&rq->stats.ctx);

	/* free leftover LRO packets, if any */
#ifdef HAVE_TURBO_LRO
	tcp_tlro_free(&rq->lro);
#else
	tcp_lro_free(&rq->lro);
#endif

	kfree(rq->mbuf);
	mlx5_wq_destroy(&rq->wq_ctrl);
}

static int
mlx5e_enable_rq(struct mlx5e_rq *rq, struct mlx5e_rq_param *param)
{
	struct mlx5e_channel *c = rq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	void *in;
	void *rqc;
	void *wq;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_rq_in) +
	    sizeof(u64) * rq->wq_ctrl.buf.npages;
	in = mlx5_vzalloc(inlen);
	if (in == NULL)
		return (-ENOMEM);

	rqc = MLX5_ADDR_OF(create_rq_in, in, ctx);
	wq = MLX5_ADDR_OF(rqc, rqc, wq);

	memcpy(rqc, param->rqc, sizeof(param->rqc));

	MLX5_SET(rqc, rqc, cqn, c->rq.cq.mcq.cqn);
	MLX5_SET(rqc, rqc, state, MLX5_RQC_STATE_RST);
	MLX5_SET(rqc, rqc, flush_in_error_en, 1);
	MLX5_SET(wq, wq, log_wq_pg_sz, rq->wq_ctrl.buf.page_shift -
	    PAGE_SHIFT);
	MLX5_SET64(wq, wq, dbr_addr, rq->wq_ctrl.db.dma);

	mlx5_fill_page_array(&rq->wq_ctrl.buf,
	    (__be64 *) MLX5_ADDR_OF(wq, wq, pas));

	err = mlx5_core_create_rq(mdev, in, inlen, &rq->rqn);

	kvfree(in);

	return (err);
}

static int
mlx5e_modify_rq(struct mlx5e_rq *rq, int curr_state, int next_state)
{
	struct mlx5e_channel *c = rq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	void *in;
	void *rqc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(modify_rq_in);
	in = mlx5_vzalloc(inlen);
	if (in == NULL)
		return (-ENOMEM);

	rqc = MLX5_ADDR_OF(modify_rq_in, in, ctx);

	MLX5_SET(modify_rq_in, in, rqn, rq->rqn);
	MLX5_SET(modify_rq_in, in, rq_state, curr_state);
	MLX5_SET(rqc, rqc, state, next_state);

	err = mlx5_core_modify_rq(mdev, in, inlen);

	kvfree(in);

	return (err);
}

static void
mlx5e_disable_rq(struct mlx5e_rq *rq)
{
	struct mlx5e_channel *c = rq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	mlx5_core_destroy_rq(mdev, rq->rqn);
}

static int
mlx5e_wait_for_min_rx_wqes(struct mlx5e_rq *rq)
{
	struct mlx5e_channel *c = rq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_wq_ll *wq = &rq->wq;
	int i;

	for (i = 0; i < 1000; i++) {
		if (wq->cur_sz >= priv->params.min_rx_wqes)
			return (0);

		msleep(4);
	}
	return (-ETIMEDOUT);
}

static int
mlx5e_open_rq(struct mlx5e_channel *c,
    struct mlx5e_rq_param *param,
    struct mlx5e_rq *rq)
{
	int err;
	int i;

	err = mlx5e_create_rq(c, param, rq);
	if (err)
		return (err);

	err = mlx5e_enable_rq(rq, param);
	if (err)
		goto err_destroy_rq;

	err = mlx5e_modify_rq(rq, MLX5_RQC_STATE_RST, MLX5_RQC_STATE_RDY);
	if (err)
		goto err_disable_rq;

	c->rq.enabled = 1;

	/*
	 * Test send queues, which will trigger
	 * "mlx5e_post_rx_wqes()":
	 */
	for (i = 0; i != c->num_tc; i++)
		mlx5e_send_nop(&c->sq[i], true);
	return (0);

err_disable_rq:
	mlx5e_disable_rq(rq);
err_destroy_rq:
	mlx5e_destroy_rq(rq);

	return (err);
}

static void
mlx5e_close_rq(struct mlx5e_rq *rq)
{
	rq->enabled = 0;
	mlx5e_modify_rq(rq, MLX5_RQC_STATE_RDY, MLX5_RQC_STATE_ERR);
}

static void
mlx5e_close_rq_wait(struct mlx5e_rq *rq)
{
	/* wait till RQ is empty */
	while (!mlx5_wq_ll_is_empty(&rq->wq)) {
		msleep(4);
		rq->cq.func(&rq->cq);
	}

	mlx5e_disable_rq(rq);
	mlx5e_destroy_rq(rq);
}

static void
mlx5e_free_sq_db(struct mlx5e_sq *sq)
{
	kfree(sq->dma_fifo);
	kfree(sq->mbuf);
}

static int
mlx5e_alloc_sq_db(struct mlx5e_sq *sq)
{
	int wq_sz = mlx5_wq_cyc_get_size(&sq->wq);
	int df_sz = wq_sz * MLX5_SEND_WQEBB_NUM_DS;

	sq->mbuf = kzalloc(wq_sz * sizeof(sq->mbuf[0]), GFP_KERNEL);
	sq->dma_fifo = kzalloc(df_sz * sizeof(*sq->dma_fifo), GFP_KERNEL);
	if (sq->mbuf == NULL || sq->dma_fifo == NULL) {
		mlx5e_free_sq_db(sq);
		return (-ENOMEM);
	}
	sq->dma_fifo_mask = df_sz - 1;

	return (0);
}

static const char *mlx5e_sq_stats_desc[] = {
	MLX5E_SQ_STATS(MLX5E_STATS_DESC)
};

static int
mlx5e_create_sq(struct mlx5e_channel *c,
    int tc,
    struct mlx5e_sq_param *param,
    struct mlx5e_sq *sq)
{
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	char buffer[16];

	void *sqc = param->sqc;
	void *sqc_wq = MLX5_ADDR_OF(sqc, sqc, wq);
	int err;

	err = mlx5_alloc_map_uar(mdev, &sq->uar);
	if (err)
		return (err);

	err = mlx5_wq_cyc_create(mdev, &param->wq, sqc_wq, &sq->wq,
	    &sq->wq_ctrl);
	if (err)
		goto err_unmap_free_uar;

	sq->wq.db = &sq->wq.db[MLX5_SND_DBR];
	sq->uar_map = sq->uar.map;
	sq->uar_bf_map  = sq->uar.bf_map;
	sq->bf_buf_size = (1 << MLX5_CAP_GEN(mdev, log_bf_reg_size)) / 2;

	err = mlx5e_alloc_sq_db(sq);
	if (err)
		goto err_sq_wq_destroy;

	sq->pdev = c->pdev;
	sq->mkey_be = c->mkey_be;
	sq->channel = c;
	sq->tc = tc;

	snprintf(buffer, sizeof(buffer), "txstat%dtc%d", c->ix, tc);
	mlx5e_create_stats(&sq->stats.ctx, SYSCTL_CHILDREN(priv->sysctl),
	    buffer, mlx5e_sq_stats_desc, MLX5E_SQ_STATS_NUM,
	    sq->stats.arg);

	return (0);

err_sq_wq_destroy:
	mlx5_wq_destroy(&sq->wq_ctrl);

err_unmap_free_uar:
	mlx5_unmap_free_uar(mdev, &sq->uar);

	return (err);
}

static void
mlx5e_destroy_sq(struct mlx5e_sq *sq)
{
	struct mlx5e_channel *c = sq->channel;
	struct mlx5e_priv *priv = c->priv;

	/* destroy all sysctl nodes */
	sysctl_ctx_free(&sq->stats.ctx);

	mlx5e_free_sq_db(sq);
	mlx5_wq_destroy(&sq->wq_ctrl);
	mlx5_unmap_free_uar(priv->mdev, &sq->uar);
}

static int
mlx5e_enable_sq(struct mlx5e_sq *sq, struct mlx5e_sq_param *param)
{
	struct mlx5e_channel *c = sq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	void *in;
	void *sqc;
	void *wq;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_sq_in) +
	    sizeof(u64) * sq->wq_ctrl.buf.npages;
	in = mlx5_vzalloc(inlen);
	if (in == NULL)
		return (-ENOMEM);

	sqc = MLX5_ADDR_OF(create_sq_in, in, ctx);
	wq = MLX5_ADDR_OF(sqc, sqc, wq);

	memcpy(sqc, param->sqc, sizeof(param->sqc));

	MLX5_SET(sqc, sqc, tis_num_0, priv->tisn[sq->tc]);
	MLX5_SET(sqc, sqc, cqn, c->sq[sq->tc].cq.mcq.cqn);
	MLX5_SET(sqc, sqc, state, MLX5_SQC_STATE_RST);
	MLX5_SET(sqc, sqc, tis_lst_sz, 1);
	MLX5_SET(sqc, sqc, flush_in_error_en, 1);

	MLX5_SET(wq, wq, wq_type, MLX5_WQ_TYPE_CYCLIC);
	MLX5_SET(wq, wq, uar_page, sq->uar.index);
	MLX5_SET(wq, wq, log_wq_pg_sz, sq->wq_ctrl.buf.page_shift -
	    PAGE_SHIFT);
	MLX5_SET64(wq, wq, dbr_addr, sq->wq_ctrl.db.dma);

	mlx5_fill_page_array(&sq->wq_ctrl.buf,
	    (__be64 *) MLX5_ADDR_OF(wq, wq, pas));

	err = mlx5_core_create_sq(mdev, in, inlen, &sq->sqn);

	kvfree(in);

	return (err);
}

static int
mlx5e_modify_sq(struct mlx5e_sq *sq, int curr_state, int next_state)
{
	struct mlx5e_channel *c = sq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	void *in;
	void *sqc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(modify_sq_in);
	in = mlx5_vzalloc(inlen);
	if (in == NULL)
		return (-ENOMEM);

	sqc = MLX5_ADDR_OF(modify_sq_in, in, ctx);

	MLX5_SET(modify_sq_in, in, sqn, sq->sqn);
	MLX5_SET(modify_sq_in, in, sq_state, curr_state);
	MLX5_SET(sqc, sqc, state, next_state);

	err = mlx5_core_modify_sq(mdev, in, inlen);

	kvfree(in);

	return (err);
}

static void
mlx5e_disable_sq(struct mlx5e_sq *sq)
{
	struct mlx5e_channel *c = sq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	mlx5_core_destroy_sq(mdev, sq->sqn);
}

static int
mlx5e_open_sq(struct mlx5e_channel *c,
    int tc,
    struct mlx5e_sq_param *param,
    struct mlx5e_sq *sq)
{
	int err;

	err = mlx5e_create_sq(c, tc, param, sq);
	if (err)
		return (err);

	err = mlx5e_enable_sq(sq, param);
	if (err)
		goto err_destroy_sq;

	err = mlx5e_modify_sq(sq, MLX5_SQC_STATE_RST, MLX5_SQC_STATE_RDY);
	if (err)
		goto err_disable_sq;

	set_bit(MLX5E_SQ_STATE_WAKE_TXQ_ENABLE, &sq->state);

	return (0);

err_disable_sq:
	mlx5e_disable_sq(sq);
err_destroy_sq:
	mlx5e_destroy_sq(sq);

	return (err);
}

static void
mlx5e_close_sq(struct mlx5e_sq *sq)
{
	clear_bit(MLX5E_SQ_STATE_WAKE_TXQ_ENABLE, &sq->state);

	/* ensure hw is notified of all pending wqes */
	if (mlx5e_sq_has_room_for(sq, 1))
		mlx5e_send_nop(sq, true);

	mlx5e_modify_sq(sq, MLX5_SQC_STATE_RDY, MLX5_SQC_STATE_ERR);
}

static void
mlx5e_close_sq_wait(struct mlx5e_sq *sq)
{
	/* wait till SQ is empty */
	while (sq->cc != sq->pc) {
		msleep(4);
		sq->cq.func(&sq->cq);
	}

	mlx5e_disable_sq(sq);
	mlx5e_destroy_sq(sq);
}

static int
mlx5e_create_cq(struct mlx5e_channel *c,
    struct mlx5e_cq_param *param,
    struct mlx5e_cq *cq,
    mlx5e_cq_func_t *func)
{
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_core_cq *mcq = &cq->mcq;
	int eqn_not_used;
	int irqn;
	int err;
	u32 i;

	param->wq.buf_numa_node = 0;
	param->wq.db_numa_node = 0;
	param->eq_ix = c->ix;

	err = mlx5_cqwq_create(mdev, &param->wq, param->cqc, &cq->wq,
	    &cq->wq_ctrl);
	if (err)
		return (err);

	mlx5_vector2eqn(mdev, param->eq_ix, &eqn_not_used, &irqn);

	mcq->cqe_sz = 64;
	mcq->set_ci_db = cq->wq_ctrl.db.db;
	mcq->arm_db = cq->wq_ctrl.db.db + 1;
	*mcq->set_ci_db = 0;
	*mcq->arm_db = 0;
	mcq->vector = param->eq_ix;
	mcq->comp = mlx5e_completion_event;
	mcq->event = mlx5e_cq_error_event;
	mcq->irqn = irqn;
	mcq->uar = &priv->cq_uar;

	for (i = 0; i < mlx5_cqwq_get_size(&cq->wq); i++) {
		struct mlx5_cqe64 *cqe = mlx5_cqwq_get_wqe(&cq->wq, i);

		cqe->op_own = 0xf1;
	}

	cq->channel = c;
	cq->func = func;

	return (0);
}

static void
mlx5e_destroy_cq(struct mlx5e_cq *cq)
{
	mlx5_wq_destroy(&cq->wq_ctrl);
}

static int
mlx5e_enable_cq(struct mlx5e_cq *cq, struct mlx5e_cq_param *param)
{
	struct mlx5e_channel *c = cq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_core_cq *mcq = &cq->mcq;
	void *in;
	void *cqc;
	int inlen;
	int irqn_not_used;
	int eqn;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_cq_in) +
	    sizeof(u64) * cq->wq_ctrl.buf.npages;
	in = mlx5_vzalloc(inlen);
	if (in == NULL)
		return (-ENOMEM);

	cqc = MLX5_ADDR_OF(create_cq_in, in, cq_context);

	memcpy(cqc, param->cqc, sizeof(param->cqc));

	mlx5_fill_page_array(&cq->wq_ctrl.buf,
	    (__be64 *) MLX5_ADDR_OF(create_cq_in, in, pas));

	mlx5_vector2eqn(mdev, param->eq_ix, &eqn, &irqn_not_used);

	MLX5_SET(cqc, cqc, c_eqn, eqn);
	MLX5_SET(cqc, cqc, uar_page, mcq->uar->index);
	MLX5_SET(cqc, cqc, log_page_size, cq->wq_ctrl.buf.page_shift -
	    PAGE_SHIFT);
	MLX5_SET64(cqc, cqc, dbr_addr, cq->wq_ctrl.db.dma);

	err = mlx5_core_create_cq(mdev, mcq, in, inlen);

	kvfree(in);

	if (err)
		return (err);

	mlx5e_cq_arm(cq);

	return (0);
}

static void
mlx5e_disable_cq(struct mlx5e_cq *cq)
{
	struct mlx5e_channel *c = cq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct mlx5_core_dev *mdev = priv->mdev;

	mlx5_core_destroy_cq(mdev, &cq->mcq);
}

static int
mlx5e_open_cq(struct mlx5e_channel *c,
    struct mlx5e_cq_param *param,
    struct mlx5e_cq *cq,
    mlx5e_cq_func_t *func)
{
	int err;

	err = mlx5e_create_cq(c, param, cq, func);
	if (err)
		return (err);

	err = mlx5e_enable_cq(cq, param);
	if (err)
		goto err_destroy_cq;

	return (0);

err_destroy_cq:
	mlx5e_destroy_cq(cq);

	return (err);
}

static void
mlx5e_close_cq(struct mlx5e_cq *cq)
{
	mlx5e_disable_cq(cq);
	mlx5e_destroy_cq(cq);
}

static int
mlx5e_open_tx_cqs(struct mlx5e_channel *c,
    struct mlx5e_channel_param *cparam)
{
	int err;
	int tc;

	for (tc = 0; tc < c->num_tc; tc++) {
		/* init mutex */
		spin_lock_init(&c->sq[tc].lock);
	}
	for (tc = 0; tc < c->num_tc; tc++) {
		/* open completion queue */
		err = mlx5e_open_cq(c, &cparam->tx_cq, &c->sq[tc].cq,
		    &mlx5e_tx_cq_function);
		if (err)
			goto err_close_tx_cqs;
	}

	return (0);

err_close_tx_cqs:
	for (tc--; tc >= 0; tc--)
		mlx5e_close_cq(&c->sq[tc].cq);

	return (err);
}

static void
mlx5e_close_tx_cqs(struct mlx5e_channel *c)
{
	int tc;

	for (tc = 0; tc < c->num_tc; tc++)
		mlx5e_close_cq(&c->sq[tc].cq);
}

static int
mlx5e_open_sqs(struct mlx5e_channel *c,
    struct mlx5e_channel_param *cparam)
{
	int err;
	int tc;

	for (tc = 0; tc < c->num_tc; tc++) {
		err = mlx5e_open_sq(c, tc, &cparam->sq, &c->sq[tc]);
		if (err)
			goto err_close_sqs;
	}

	return (0);

err_close_sqs:
	for (tc--; tc >= 0; tc--) {
		mlx5e_close_sq(&c->sq[tc]);
		mlx5e_close_sq_wait(&c->sq[tc]);
	}

	return (err);
}

static void
mlx5e_close_sqs(struct mlx5e_channel *c)
{
	int tc;

	for (tc = 0; tc < c->num_tc; tc++)
		mlx5e_close_sq(&c->sq[tc]);
}

static void
mlx5e_close_sqs_wait(struct mlx5e_channel *c)
{
	int tc;

	for (tc = 0; tc < c->num_tc; tc++)
		mlx5e_close_sq_wait(&c->sq[tc]);
}

static int
mlx5e_open_channel(struct mlx5e_priv *priv, int ix,
    struct mlx5e_channel_param *cparam,
    struct mlx5e_channel * volatile *cp)
{
	struct mlx5e_channel *c;
	int err;

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (c == NULL)
		return (-ENOMEM);

	c->priv = priv;
	c->ix = ix;
	c->cpu = 0;
	c->pdev = &priv->mdev->pdev->dev;
	c->netdev = priv->netdev;
	c->mkey_be = cpu_to_be32(priv->mr.key);
	c->num_tc = priv->num_tc;

	err = mlx5e_open_tx_cqs(c, cparam);
	if (err)
		goto err_free;

	/* receive completion queue lock */
	spin_lock_init(&c->rq.lock);

	/* open completion queue */
	err = mlx5e_open_cq(c, &cparam->rx_cq, &c->rq.cq,
	    &mlx5e_rx_cq_function);
	if (err)
		goto err_close_tx_cqs;

	err = mlx5e_open_sqs(c, cparam);
	if (err)
		goto err_close_rx_cq;

	err = mlx5e_open_rq(c, &cparam->rq, &c->rq);
	if (err)
		goto err_close_sqs;

	/* store channel pointer */
	*cp = c;

	/* poll receive queue initially */
	c->rq.cq.func(&c->rq.cq);

	return (0);

err_close_sqs:
	mlx5e_close_sqs(c);
	mlx5e_close_sqs_wait(c);

err_close_rx_cq:
	mlx5e_close_cq(&c->rq.cq);

err_close_tx_cqs:
	mlx5e_close_tx_cqs(c);

err_free:
	kfree(c);
	return (err);
}

static void
mlx5e_close_channel(struct mlx5e_channel * volatile *pp)
{
	struct mlx5e_channel *c = *pp;

	/* check if channel is already closed */
	if (c == NULL)
		return;
	mlx5e_close_rq(&c->rq);
	mlx5e_close_sqs(c);
}

static void
mlx5e_close_channel_wait(struct mlx5e_channel * volatile *pp)
{
	struct mlx5e_channel *c = *pp;

	/* check if channel is already closed */
	if (c == NULL)
		return;
	/* ensure channel pointer is no longer used */
	*pp = NULL;

	mlx5e_close_rq_wait(&c->rq);
	mlx5e_close_sqs_wait(c);
	mlx5e_close_cq(&c->rq.cq);
	mlx5e_close_tx_cqs(c);
	kfree(c);
}

static void
mlx5e_build_rq_param(struct mlx5e_priv *priv,
    struct mlx5e_rq_param *param)
{
	void *rqc = param->rqc;
	void *wq = MLX5_ADDR_OF(rqc, rqc, wq);

	MLX5_SET(wq, wq, wq_type, MLX5_WQ_TYPE_LINKED_LIST);
	MLX5_SET(wq, wq, end_padding_mode, MLX5_WQ_END_PAD_MODE_ALIGN);
	MLX5_SET(wq, wq, log_wq_stride, ilog2(sizeof(struct mlx5e_rx_wqe)));
	MLX5_SET(wq, wq, log_wq_sz, priv->params.log_rq_size);
	MLX5_SET(wq, wq, pd, priv->pdn);

	param->wq.buf_numa_node = 0;
	param->wq.db_numa_node = 0;
	param->wq.linear = 1;
}

static void
mlx5e_build_sq_param(struct mlx5e_priv *priv,
    struct mlx5e_sq_param *param)
{
	void *sqc = param->sqc;
	void *wq = MLX5_ADDR_OF(sqc, sqc, wq);

	MLX5_SET(wq, wq, log_wq_sz, priv->params.log_sq_size);
	MLX5_SET(wq, wq, log_wq_stride, ilog2(MLX5_SEND_WQE_BB));
	MLX5_SET(wq, wq, pd, priv->pdn);

	param->wq.buf_numa_node = 0;
	param->wq.db_numa_node = 0;
}

static void
mlx5e_build_common_cq_param(struct mlx5e_priv *priv,
    struct mlx5e_cq_param *param)
{
	void *cqc = param->cqc;

	MLX5_SET(cqc, cqc, uar_page, priv->cq_uar.index);
}

static void
mlx5e_build_rx_cq_param(struct mlx5e_priv *priv,
    struct mlx5e_cq_param *param)
{
	void *cqc = param->cqc;

	MLX5_SET(cqc, cqc, log_cq_size, priv->params.log_rq_size);
	MLX5_SET(cqc, cqc, cq_period, priv->params.rx_cq_moderation_usec);
	MLX5_SET(cqc, cqc, cq_max_count, priv->params.rx_cq_moderation_pkts);

	mlx5e_build_common_cq_param(priv, param);
}

static void
mlx5e_build_tx_cq_param(struct mlx5e_priv *priv,
    struct mlx5e_cq_param *param)
{
	void *cqc = param->cqc;

	MLX5_SET(cqc, cqc, log_cq_size, priv->params.log_sq_size);
	MLX5_SET(cqc, cqc, cq_period, priv->params.tx_cq_moderation_usec);
	MLX5_SET(cqc, cqc, cq_max_count, priv->params.tx_cq_moderation_pkts);

	mlx5e_build_common_cq_param(priv, param);
}

static void
mlx5e_build_channel_param(struct mlx5e_priv *priv,
    struct mlx5e_channel_param *cparam)
{
	memset(cparam, 0, sizeof(*cparam));

	mlx5e_build_rq_param(priv, &cparam->rq);
	mlx5e_build_sq_param(priv, &cparam->sq);
	mlx5e_build_rx_cq_param(priv, &cparam->rx_cq);
	mlx5e_build_tx_cq_param(priv, &cparam->tx_cq);
}

static int
mlx5e_open_channels(struct mlx5e_priv *priv)
{
	struct mlx5e_channel_param cparam;
	int err;
	int i;
	int j;

	priv->channel = kcalloc(priv->params.num_channels,
	    sizeof(struct mlx5e_channel *), GFP_KERNEL);
	if (priv->channel == NULL)
		return (-ENOMEM);

	mlx5e_build_channel_param(priv, &cparam);
	for (i = 0; i < priv->params.num_channels; i++) {
		err = mlx5e_open_channel(priv, i, &cparam, &priv->channel[i]);
		if (err)
			goto err_close_channels;
	}

	for (j = 0; j < priv->params.num_channels; j++) {
		err = mlx5e_wait_for_min_rx_wqes(&priv->channel[j]->rq);
		if (err)
			goto err_close_channels;
	}

	return (0);

err_close_channels:
	for (i--; i >= 0; i--) {
		mlx5e_close_channel(&priv->channel[i]);
		mlx5e_close_channel_wait(&priv->channel[i]);
	}

	kfree(priv->channel);
	priv->channel = NULL;

	return (err);
}

static void
mlx5e_close_channels(struct mlx5e_priv *priv)
{
	int i;

	if (priv->channel == NULL)
		return;

	for (i = 0; i < priv->params.num_channels; i++)
		mlx5e_close_channel(&priv->channel[i]);
	for (i = 0; i < priv->params.num_channels; i++)
		mlx5e_close_channel_wait(&priv->channel[i]);

	kfree(priv->channel);
	priv->channel = NULL;
}

static int
mlx5e_open_tis(struct mlx5e_priv *priv, int tc)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 in[MLX5_ST_SZ_DW(create_tis_in)];
	void *tisc = MLX5_ADDR_OF(create_tis_in, in, ctx);

	memset(in, 0, sizeof(in));

	MLX5_SET(tisc, tisc, prio, tc);

	return (mlx5_core_create_tis(mdev, in, sizeof(in), &priv->tisn[tc]));
}

static void
mlx5e_close_tis(struct mlx5e_priv *priv, int tc)
{
	mlx5_core_destroy_tis(priv->mdev, priv->tisn[tc]);
}

static int
mlx5e_open_tises(struct mlx5e_priv *priv)
{
	int num_tc = priv->num_tc;
	int err;
	int tc;

	for (tc = 0; tc < num_tc; tc++) {
		err = mlx5e_open_tis(priv, tc);
		if (err)
			goto err_close_tises;
	}

	return (0);

err_close_tises:
	for (tc--; tc >= 0; tc--)
		mlx5e_close_tis(priv, tc);

	return (err);
}

static void
mlx5e_close_tises(struct mlx5e_priv *priv)
{
	int num_tc = priv->num_tc;
	int tc;

	for (tc = 0; tc < num_tc; tc++)
		mlx5e_close_tis(priv, tc);
}

static int
mlx5e_open_rqt(struct mlx5e_priv *priv)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 *in;
	u32 out[MLX5_ST_SZ_DW(create_rqt_out)];
	void *rqtc;
	int inlen;
	int err;
	int sz;
	int i;

	sz = 1 << priv->params.rx_hash_log_tbl_sz;

	inlen = MLX5_ST_SZ_BYTES(create_rqt_in) + sizeof(u32) * sz;
	in = mlx5_vzalloc(inlen);
	if (in == NULL)
		return (-ENOMEM);
	rqtc = MLX5_ADDR_OF(create_rqt_in, in, rqt_context);

	MLX5_SET(rqtc, rqtc, rqt_actual_size, sz);
	MLX5_SET(rqtc, rqtc, rqt_max_size, sz);

	for (i = 0; i < sz; i++) {
		int ix = i % priv->params.num_channels;

		MLX5_SET(rqtc, rqtc, rq_num[i], priv->channel[ix]->rq.rqn);
	}

	MLX5_SET(create_rqt_in, in, opcode, MLX5_CMD_OP_CREATE_RQT);

	memset(out, 0, sizeof(out));
	err = mlx5_cmd_exec_check_status(mdev, in, inlen, out, sizeof(out));
	if (!err)
		priv->rqtn = MLX5_GET(create_rqt_out, out, rqtn);

	kvfree(in);

	return (err);
}

static void
mlx5e_close_rqt(struct mlx5e_priv *priv)
{
	u32 in[MLX5_ST_SZ_DW(destroy_rqt_in)];
	u32 out[MLX5_ST_SZ_DW(destroy_rqt_out)];

	memset(in, 0, sizeof(in));

	MLX5_SET(destroy_rqt_in, in, opcode, MLX5_CMD_OP_DESTROY_RQT);
	MLX5_SET(destroy_rqt_in, in, rqtn, priv->rqtn);

	mlx5_cmd_exec_check_status(priv->mdev, in, sizeof(in), out,
	    sizeof(out));
}

static void
mlx5e_build_tir_ctx(struct mlx5e_priv *priv, u32 * tirc, int tt)
{
	void *hfso = MLX5_ADDR_OF(tirc, tirc, rx_hash_field_selector_outer);
	__be32 *hkey;

#define	ROUGH_MAX_L2_L3_HDR_SZ 256

#define	MLX5_HASH_IP     (MLX5_HASH_FIELD_SEL_SRC_IP   |\
			  MLX5_HASH_FIELD_SEL_DST_IP)

#define	MLX5_HASH_ALL    (MLX5_HASH_FIELD_SEL_SRC_IP   |\
			  MLX5_HASH_FIELD_SEL_DST_IP   |\
			  MLX5_HASH_FIELD_SEL_L4_SPORT |\
			  MLX5_HASH_FIELD_SEL_L4_DPORT)

	switch (tt) {
	case MLX5E_TT_ANY:
		MLX5_SET(tirc, tirc, disp_type,
		    MLX5_TIRC_DISP_TYPE_DIRECT);
		MLX5_SET(tirc, tirc, inline_rqn,
		    priv->channel[0]->rq.rqn);
		break;
	default:
		MLX5_SET(tirc, tirc, disp_type,
		    MLX5_TIRC_DISP_TYPE_INDIRECT);
		MLX5_SET(tirc, tirc, indirect_table,
		    priv->rqtn);
		MLX5_SET(tirc, tirc, rx_hash_fn,
		    MLX5_TIRC_RX_HASH_FN_HASH_TOEPLITZ);
		MLX5_SET(tirc, tirc, rx_hash_symmetric, 1);
		hkey = (__be32 *) MLX5_ADDR_OF(tirc, tirc, rx_hash_toeplitz_key);
		hkey[0] = cpu_to_be32(0xD181C62C);
		hkey[1] = cpu_to_be32(0xF7F4DB5B);
		hkey[2] = cpu_to_be32(0x1983A2FC);
		hkey[3] = cpu_to_be32(0x943E1ADB);
		hkey[4] = cpu_to_be32(0xD9389E6B);
		hkey[5] = cpu_to_be32(0xD1039C2C);
		hkey[6] = cpu_to_be32(0xA74499AD);
		hkey[7] = cpu_to_be32(0x593D56D9);
		hkey[8] = cpu_to_be32(0xF3253C06);
		hkey[9] = cpu_to_be32(0x2ADC1FFC);
		break;
	}

	switch (tt) {
	case MLX5E_TT_IPV4_TCP:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
		    MLX5_L3_PROT_TYPE_IPV4);
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
		    MLX5_L4_PROT_TYPE_TCP);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
		    MLX5_HASH_ALL);
		break;

	case MLX5E_TT_IPV6_TCP:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
		    MLX5_L3_PROT_TYPE_IPV6);
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
		    MLX5_L4_PROT_TYPE_TCP);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
		    MLX5_HASH_ALL);
		break;

	case MLX5E_TT_IPV4_UDP:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
		    MLX5_L3_PROT_TYPE_IPV4);
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
		    MLX5_L4_PROT_TYPE_UDP);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
		    MLX5_HASH_ALL);
		break;

	case MLX5E_TT_IPV6_UDP:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
		    MLX5_L3_PROT_TYPE_IPV6);
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
		    MLX5_L4_PROT_TYPE_UDP);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
		    MLX5_HASH_ALL);
		break;

	case MLX5E_TT_IPV4:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
		    MLX5_L3_PROT_TYPE_IPV4);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
		    MLX5_HASH_IP);
		break;

	case MLX5E_TT_IPV6:
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
		    MLX5_L3_PROT_TYPE_IPV6);
		MLX5_SET(rx_hash_field_select, hfso, selected_fields,
		    MLX5_HASH_IP);
		break;
	}
}

static int
mlx5e_open_tir(struct mlx5e_priv *priv, int tt)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 *in;
	void *tirc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = mlx5_vzalloc(inlen);
	if (in == NULL)
		return (-ENOMEM);
	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);

	mlx5e_build_tir_ctx(priv, tirc, tt);

	err = mlx5_core_create_tir(mdev, in, inlen, &priv->tirn[tt]);

	kvfree(in);

	return (err);
}

static void
mlx5e_close_tir(struct mlx5e_priv *priv, int tt)
{
	mlx5_core_destroy_tir(priv->mdev, priv->tirn[tt]);
}

static int
mlx5e_open_tirs(struct mlx5e_priv *priv)
{
	int err;
	int i;

	for (i = 0; i < MLX5E_NUM_TT; i++) {
		err = mlx5e_open_tir(priv, i);
		if (err)
			goto err_close_tirs;
	}

	return (0);

err_close_tirs:
	for (i--; i >= 0; i--)
		mlx5e_close_tir(priv, i);

	return (err);
}

static void
mlx5e_close_tirs(struct mlx5e_priv *priv)
{
	int i;

	for (i = 0; i < MLX5E_NUM_TT; i++)
		mlx5e_close_tir(priv, i);
}

static int
mlx5e_set_dev_port_mtu(struct net_device *netdev, int sw_mtu)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_core_dev *mdev = priv->mdev;
	int hw_mtu;
	int err;

	err = mlx5_set_port_mtu(mdev, sw_mtu + MLX5E_MTU_OVERHEAD);
	if (err)
		return (err);

	mlx5_query_port_oper_mtu(mdev, &hw_mtu);

	netdev->if_mtu = (hw_mtu - MLX5E_MTU_OVERHEAD);

	if (netdev->if_mtu != sw_mtu) {
		if_printf(netdev, "Port MTU %d is different than "
		    "netdev mtu %d\n", sw_mtu, netdev->if_mtu);
	}
	return (0);
}

int
mlx5e_open_locked(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	int err;

	/* check if already opened */
	if (test_bit(MLX5E_STATE_OPENED, &priv->state) != 0)
		return (0);

	err = mlx5e_open_tises(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_open_tises failed, %d\n",
		    __func__, err);
		return (err);
	}
	err = mlx5e_open_channels(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_open_channels failed, %d\n",
		    __func__, err);
		goto err_close_tises;
	}
	err = mlx5e_open_rqt(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_open_rqt failed, %d\n",
		    __func__, err);
		goto err_close_channels;
	}
	err = mlx5e_open_tirs(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_open_tir failed, %d\n",
		    __func__, err);
		goto err_close_rqls;
	}
	err = mlx5e_open_flow_table(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_open_flow_table failed, %d\n",
		    __func__, err);
		goto err_close_tirs;
	}
	err = mlx5e_add_all_vlan_rules(priv);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_add_all_vlan_rules failed, %d\n",
		    __func__, err);
		goto err_close_flow_table;
	}
	set_bit(MLX5E_STATE_OPENED, &priv->state);

	mlx5e_update_carrier(priv);
	mlx5e_set_rx_mode_core(priv);

	return (0);

err_close_flow_table:
	mlx5e_close_flow_table(priv);

err_close_tirs:
	mlx5e_close_tirs(priv);

err_close_rqls:
	mlx5e_close_rqt(priv);

err_close_channels:
	mlx5e_close_channels(priv);

err_close_tises:
	mlx5e_close_tises(priv);

	return (err);
}

static void
mlx5e_open(void *arg)
{
	struct mlx5e_priv *priv = arg;

	mutex_lock(&priv->state_lock);
	mlx5e_open_locked(priv->netdev);
	priv->netdev->if_drv_flags |= IFF_DRV_RUNNING;
	mutex_unlock(&priv->state_lock);
}

int
mlx5e_close_locked(struct net_device *netdev)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	/* check if already closed */
	if (test_bit(MLX5E_STATE_OPENED, &priv->state) == 0)
		return (0);

	clear_bit(MLX5E_STATE_OPENED, &priv->state);

	mlx5e_set_rx_mode_core(priv);
	mlx5e_del_all_vlan_rules(priv);
	if_link_state_change(priv->netdev, LINK_STATE_DOWN);
	mlx5e_close_flow_table(priv);
	mlx5e_close_tirs(priv);
	mlx5e_close_rqt(priv);
	mlx5e_close_channels(priv);
	mlx5e_close_tises(priv);

	return (0);
}

static uint64_t
mlx5e_get_counter(struct ifnet *netdevice, ift_counter cnt)
{
	struct mlx5e_priv *priv = netdevice->if_softc;
	u64 retval;

	/* mutex_lock(&priv->state_lock); XXX not allowed */
	switch (cnt) {
	case IFCOUNTER_IPACKETS:
		retval = priv->stats.vport.rx_packets;
		break;
	case IFCOUNTER_IERRORS:
		retval = priv->stats.vport.rx_error_packets;
		break;
	case IFCOUNTER_OPACKETS:
		retval = priv->stats.vport.tx_packets;
		break;
	case IFCOUNTER_OERRORS:
		retval = priv->stats.vport.tx_error_packets;
		break;
	case IFCOUNTER_IBYTES:
		retval = priv->stats.vport.rx_bytes;
		break;
	case IFCOUNTER_OBYTES:
		retval = priv->stats.vport.tx_bytes;
		break;
	case IFCOUNTER_IMCASTS:
		retval = priv->stats.vport.rx_multicast_packets;
		break;
	case IFCOUNTER_OMCASTS:
		retval = priv->stats.vport.tx_multicast_packets;
		break;
	case IFCOUNTER_OQDROPS:
		retval = priv->stats.vport.tx_queue_dropped;
		break;
	default:
		retval = if_get_counter_default(netdevice, cnt);
		break;
	}
	/* mutex_unlock(&priv->state_lock); XXX not allowed */
	return (retval);
}

static void
mlx5e_set_rx_mode(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);

	schedule_work(&priv->set_rx_mode_work);
}

static int
mlx5e_ioctl(struct ifnet *netdev, u_long command, caddr_t data)
{
	struct mlx5e_priv *priv;
	struct ifreq *ifr;
	int error = 0;
	int mask = 0;
	int value = 0;

	priv = netdev->if_softc;

	switch (command) {
	case SIOCSIFMTU:
		ifr = (struct ifreq *)data;

		if (ifr->ifr_mtu > 0 &&
		    ifr->ifr_mtu + MLX5E_MTU_OVERHEAD <= MLX5E_MTU_MAX) {
			int was_opened;

			mutex_lock(&priv->state_lock);
			was_opened = test_bit(MLX5E_STATE_OPENED, &priv->state);
			if (was_opened)
				mlx5e_close_locked(netdev);

			/* set new MTU */
			mlx5e_set_dev_port_mtu(netdev, ifr->ifr_mtu);

			if (was_opened)
				mlx5e_open_locked(netdev);
			mutex_unlock(&priv->state_lock);
		} else {
			error = EINVAL;
		}
		break;
	case SIOCSIFFLAGS:
		if (netdev->if_flags & IFF_UP) {
			if ((netdev->if_drv_flags & IFF_DRV_RUNNING) == 0) {
				mutex_lock(&priv->state_lock);
				if (test_bit(MLX5E_STATE_OPENED, &priv->state) == 0)
					mlx5e_open_locked(netdev);
				netdev->if_drv_flags |= IFF_DRV_RUNNING;
				mutex_unlock(&priv->state_lock);
			} else {
				mlx5e_set_rx_mode(netdev);
			}
		} else {
			mutex_lock(&priv->state_lock);
			if (netdev->if_drv_flags & IFF_DRV_RUNNING) {
				if (test_bit(MLX5E_STATE_OPENED, &priv->state) != 0)
					mlx5e_close_locked(netdev);
				netdev->if_drv_flags &= ~IFF_DRV_RUNNING;
				if_link_state_change(netdev, LINK_STATE_DOWN);
			}
			mutex_unlock(&priv->state_lock);
		}
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		mlx5e_set_rx_mode(netdev);
		break;
	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA:
	case SIOCGIFXMEDIA:
		ifr = (struct ifreq *)data;
		error = ifmedia_ioctl(netdev, ifr, &priv->media, command);
		break;
	case SIOCSIFCAP:
		ifr = (struct ifreq *)data;
		mutex_lock(&priv->state_lock);
		mask = (ifr->ifr_reqcap ^ netdev->if_capenable) &
		    (IFCAP_HWCSUM | IFCAP_TSO4 | IFCAP_TSO6 | IFCAP_LRO |
		    IFCAP_VLAN_HWTAGGING | IFCAP_VLAN_HWFILTER |
		    IFCAP_WOL_MAGIC);
		netdev->if_capenable ^= mask;
		value = netdev->if_capenable;
		mutex_unlock(&priv->state_lock);
		if (mask & IFCAP_VLAN_HWFILTER) {
			if (value & IFCAP_VLAN_HWFILTER)
				mlx5e_enable_vlan_filter(priv);
			else
				mlx5e_disable_vlan_filter(priv);
		}
		VLAN_CAPABILITIES(netdev);
		break;
	default:
		error = ether_ioctl(netdev, command, data);
		break;
	}
	return (error);
}

static int
mlx5e_check_required_hca_cap(struct mlx5_core_dev *mdev)
{
	/*
	 * TODO: uncoment once FW really sets all these bits if
	 * (!mdev->caps.eth.rss_ind_tbl_cap || !mdev->caps.eth.csum_cap ||
	 * !mdev->caps.eth.max_lso_cap || !mdev->caps.eth.vlan_cap ||
	 * !(mdev->caps.gen.flags & MLX5_DEV_CAP_FLAG_SCQE_BRK_MOD)) return
	 * -ENOTSUPP;
	 */

	/* TODO: add more must-to-have features */

	return (0);
}

static void
mlx5e_build_netdev_priv(struct mlx5_core_dev *mdev,
    struct mlx5e_priv *priv,
    int num_comp_vectors)
{
	/*
	 * TODO: Consider link speed for setting "log_sq_size",
	 * "log_rq_size" and "cq_moderation_xxx":
	 */
	priv->params.log_sq_size =
	    MLX5E_PARAMS_DEFAULT_LOG_SQ_SIZE;
	priv->params.log_rq_size =
	    MLX5E_PARAMS_DEFAULT_LOG_RQ_SIZE;
	priv->params.rx_cq_moderation_usec =
	    MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC;
	priv->params.rx_cq_moderation_pkts =
	    MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_PKTS;
	priv->params.tx_cq_moderation_usec =
	    MLX5E_PARAMS_DEFAULT_TX_CQ_MODERATION_USEC;
	priv->params.tx_cq_moderation_pkts =
	    MLX5E_PARAMS_DEFAULT_TX_CQ_MODERATION_PKTS;
	priv->params.min_rx_wqes =
	    MLX5E_PARAMS_DEFAULT_MIN_RX_WQES;
	priv->params.rx_hash_log_tbl_sz =
	    (order_base_2(num_comp_vectors) >
	    MLX5E_PARAMS_DEFAULT_RX_HASH_LOG_TBL_SZ) ?
	    order_base_2(num_comp_vectors) :
	    MLX5E_PARAMS_DEFAULT_RX_HASH_LOG_TBL_SZ;
	priv->params.num_tc = 1;
	priv->params.default_vlan_prio = 0;

	priv->mdev = mdev;
	priv->params.num_channels = num_comp_vectors;
	priv->order_base_2_num_channels = order_base_2(num_comp_vectors);
	priv->queue_mapping_channel_mask =
	    roundup_pow_of_two(num_comp_vectors) - 1;
	priv->num_tc = priv->params.num_tc;
	priv->default_vlan_prio = priv->params.default_vlan_prio;

	spin_lock_init(&priv->async_events_spinlock);
	mutex_init(&priv->state_lock);

	INIT_WORK(&priv->update_stats_work, mlx5e_update_stats_work);
	INIT_WORK(&priv->update_carrier_work, mlx5e_update_carrier_work);
	INIT_WORK(&priv->set_rx_mode_work, mlx5e_set_rx_mode_work);
}

static int
mlx5e_create_mkey(struct mlx5e_priv *priv, u32 pdn,
    struct mlx5_core_mr *mr)
{
	struct net_device *netdev = priv->netdev;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_create_mkey_mbox_in *in;
	int err;

	in = mlx5_vzalloc(sizeof(*in));
	if (in == NULL) {
		netdev_err(netdev, "%s: failed to allocate inbox\n", __func__);
		return (-ENOMEM);
	}
	in->seg.flags = MLX5_PERM_LOCAL_WRITE |
	    MLX5_PERM_LOCAL_READ |
	    MLX5_ACCESS_MODE_PA;
	in->seg.flags_pd = cpu_to_be32(pdn | MLX5_MKEY_LEN64);
	in->seg.qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);

	err = mlx5_core_create_mkey(mdev, mr, in, sizeof(*in), NULL, NULL,
	    NULL);
	if (err)
		netdev_err(netdev, "%s: mlx5_core_create_mkey failed, %d\n",
		    __func__, err);

	kvfree(in);

	return (err);
}

static const char *mlx5e_vport_stats_desc[] = {
	MLX5E_VPORT_STATS(MLX5E_STATS_DESC)
};

static const char *mlx5e_pport_stats_desc[] = {
	MLX5E_PPORT_STATS(MLX5E_STATS_DESC)
};

static void *
mlx5e_create_netdev(struct mlx5_core_dev *mdev)
{
	static volatile int mlx5_en_unit;
	struct net_device *netdev;
	struct mlx5e_priv *priv;
	u8 dev_addr[ETHER_ADDR_LEN] __aligned(4);
	int ncv = mdev->priv.eq_table.num_comp_vectors;
	int err;

	if (mlx5e_check_required_hca_cap(mdev)) {
		mlx5_core_dbg(mdev, "mlx5e_check_required_hca_cap() failed\n");
		return (NULL);
	}
	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (priv == NULL) {
		mlx5_core_err(mdev, "kzalloc() failed\n");
		return (NULL);
	}
	setup_timer(&priv->watchdog, &mlx5e_update_stats, (uintptr_t)priv);
	
	netdev = priv->netdev = if_alloc(IFT_ETHER);
	if (netdev == NULL) {
		mlx5_core_err(mdev, "if_alloc() failed\n");
		kfree(priv);
		return (NULL);
	}
	netdev->if_softc = priv;
	if_initname(netdev, "mlx5en", atomic_fetchadd_int(&mlx5_en_unit, 1));
	netdev->if_mtu = ETHERMTU;
	netdev->if_init = mlx5e_open;
	netdev->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
	netdev->if_ioctl = mlx5e_ioctl;
	netdev->if_transmit = mlx5e_xmit;
	netdev->if_qflush = if_qflush;
	netdev->if_get_counter = mlx5e_get_counter;
	netdev->if_snd.ifq_maxlen = ifqmaxlen;
	/*
         * Set driver features
         */
	netdev->if_capabilities |= IFCAP_RXCSUM | IFCAP_TXCSUM;
	netdev->if_capabilities |= IFCAP_VLAN_MTU | IFCAP_VLAN_HWTAGGING;
	netdev->if_capabilities |= IFCAP_VLAN_HWCSUM | IFCAP_VLAN_HWFILTER;
	netdev->if_capabilities |= IFCAP_LINKSTATE | IFCAP_JUMBO_MTU;
	netdev->if_capabilities |= IFCAP_LRO;
	netdev->if_capabilities |= IFCAP_TSO4 | IFCAP_TSO6 | IFCAP_VLAN_HWTSO;

	/* set TSO limits so that we don't have to drop TX packets */
	netdev->if_hw_tsomax = 65536 - (ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN);
	netdev->if_hw_tsomaxsegcount = MLX5E_MAX_TX_MBUF_FRAGS - 1 /* hdr */;
	netdev->if_hw_tsomaxsegsize = 65536;	/* XXX can do up to 4GByte */

	netdev->if_capenable = netdev->if_capabilities;
	netdev->if_hwassist = 0;
	if (netdev->if_capenable & (IFCAP_TSO4 | IFCAP_TSO6))
		netdev->if_hwassist |= CSUM_TSO;
	if (netdev->if_capenable & IFCAP_TXCSUM)
		netdev->if_hwassist |= (CSUM_TCP | CSUM_UDP | CSUM_IP);

	sysctl_ctx_init(&priv->sysctl_ctx);
	priv->sysctl = SYSCTL_ADD_NODE(&priv->sysctl_ctx, SYSCTL_STATIC_CHILDREN(_hw),
	    OID_AUTO, netdev->if_xname, CTLFLAG_RD, 0, "MLX5 ethernet");
	if (priv->sysctl == NULL) {
		mlx5_core_err(mdev, "SYSCTL_ADD_NODE() failed\n");
		goto err_free_netdev;
	}
	mlx5e_build_netdev_priv(mdev, priv, ncv);

	err = mlx5_alloc_map_uar(mdev, &priv->cq_uar);
	if (err) {
		netdev_err(netdev, "%s: mlx5_alloc_map_uar failed, %d\n",
		    __func__, err);
		goto err_free_sysctl;
	}
	err = mlx5_core_alloc_pd(mdev, &priv->pdn);
	if (err) {
		netdev_err(netdev, "%s: mlx5_core_alloc_pd failed, %d\n",
		    __func__, err);
		goto err_unmap_free_uar;
	}
	err = mlx5e_create_mkey(priv, priv->pdn, &priv->mr);
	if (err) {
		netdev_err(netdev, "%s: mlx5e_create_mkey failed, %d\n",
		    __func__, err);
		goto err_dealloc_pd;
	}
	mlx5_query_nic_vport_mac_address(priv->mdev, dev_addr);

	/* set default MTU */
	mlx5e_set_dev_port_mtu(netdev, netdev->if_mtu);

	ether_ifattach(netdev, dev_addr);

	/* Register for VLAN events */
	priv->vlan_attach = EVENTHANDLER_REGISTER(vlan_config,
	    mlx5e_vlan_rx_add_vid, priv, EVENTHANDLER_PRI_FIRST);
	priv->vlan_detach = EVENTHANDLER_REGISTER(vlan_unconfig,
	    mlx5e_vlan_rx_kill_vid, priv, EVENTHANDLER_PRI_FIRST);

	/* Set default media status */
	priv->media_status_last = IFM_AVALID;
	priv->media_active_last = IFM_ETHER | IFM_AUTO;

	/* Link is down by default */
	if_link_state_change(netdev, LINK_STATE_DOWN);

	/* Setup supported medias */
	ifmedia_init(&priv->media, IFM_IMASK | IFM_ETH_FMASK,
	    mlx5e_media_change, mlx5e_media_status);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_1000_CX_SGMII | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_1000_KX | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_10G_CX4 | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_10G_KX4 | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_10G_KR | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_40G_CR4 | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_40G_KR4 | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_10G_CR1 | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_10G_SR | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_10G_ER | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_40G_SR4 | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_40G_LR4 | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_100G_CR4 | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_100G_SR4 | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_100G_KR4 | IFM_FDX, 0, NULL);
	ifmedia_add(&priv->media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&priv->media, IFM_ETHER | IFM_AUTO);

	mlx5e_enable_async_events(priv);

	mlx5e_create_stats(&priv->stats.vport.ctx, SYSCTL_CHILDREN(priv->sysctl),
	    "vstats", mlx5e_vport_stats_desc, MLX5E_VPORT_STATS_NUM,
	    priv->stats.vport.arg);

	mlx5e_create_stats(&priv->stats.pport.ctx, SYSCTL_CHILDREN(priv->sysctl),
	    "pstats", mlx5e_pport_stats_desc, MLX5E_PPORT_STATS_NUM,
	    priv->stats.pport.arg);

	mlx5e_create_ethtool(priv);

	mod_timer(&priv->watchdog, jiffies + HZ);
	
	return (priv);

err_dealloc_pd:
	mlx5_core_dealloc_pd(mdev, priv->pdn);

err_unmap_free_uar:
	mlx5_unmap_free_uar(mdev, &priv->cq_uar);

err_free_sysctl:
	sysctl_ctx_free(&priv->sysctl_ctx);

err_free_netdev:
	if_free(netdev);
	return (NULL);
}

static void
mlx5e_destroy_netdev(struct mlx5_core_dev *mdev, void *vpriv)
{
	struct mlx5e_priv *priv = vpriv;
	struct net_device *netdev = priv->netdev;

	/* stop watchdog timer */
	del_timer_sync(&priv->watchdog);
	
	if (priv->vlan_attach != NULL)
		EVENTHANDLER_DEREGISTER(vlan_config, priv->vlan_attach);
	if (priv->vlan_detach != NULL)
		EVENTHANDLER_DEREGISTER(vlan_unconfig, priv->vlan_detach);

	/* make sure device gets closed */
	mutex_lock(&priv->state_lock);
	mlx5e_close_locked(netdev);
	mutex_unlock(&priv->state_lock);

	/* destroy all remaining sysctl nodes */
	sysctl_ctx_free(&priv->stats.vport.ctx);
	sysctl_ctx_free(&priv->stats.pport.ctx);
	sysctl_ctx_free(&priv->sysctl_ctx);

	/* Unregister device - this will close the port if it was up */
	ether_ifdetach(netdev);

	mlx5_core_destroy_mkey(priv->mdev, &priv->mr);
	mlx5_core_dealloc_pd(priv->mdev, priv->pdn);
	mlx5_unmap_free_uar(priv->mdev, &priv->cq_uar);
	mlx5e_disable_async_events(priv);
	flush_scheduled_work();
	if_free(netdev);
	kfree(priv);
}

static void *
mlx5e_get_netdev(void *vpriv)
{
	struct mlx5e_priv *priv = vpriv;

	return (priv->netdev);
}

static struct mlx5_interface mlx5e_interface = {
	.add = mlx5e_create_netdev,
	.remove = mlx5e_destroy_netdev,
	.event = mlx5e_async_event,
	.protocol = MLX5_INTERFACE_PROTOCOL_ETH,
	.get_dev = mlx5e_get_netdev,
};

void
mlx5e_init(void)
{
	mlx5_register_interface(&mlx5e_interface);
}

void
mlx5e_cleanup(void)
{
	mlx5_unregister_interface(&mlx5e_interface);
}

module_init_order(mlx5e_init, SI_ORDER_THIRD);
module_exit_order(mlx5e_cleanup, SI_ORDER_THIRD);

MODULE_DEPEND(mlx5en, linuxapi, 1, 1, 1);
MODULE_DEPEND(mlx5en, mlx5, 1, 1, 1);
MODULE_VERSION(mlx5en, 1);
