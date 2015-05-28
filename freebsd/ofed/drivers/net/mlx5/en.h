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

#ifndef _MLX5_EN_H_
#define	_MLX5_EN_H_

#include <linux/page.h>
#include <linux/slab.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_lro.h>
#include <netinet/udp.h>

#ifdef HAVE_TURBO_LRO
#include "tcp_tlro.h"
#endif

#include <linux/mlx5/driver.h>
#include <linux/mlx5/qp.h>
#include <linux/mlx5/cq.h>
#include <linux/mlx5/vport.h>

#include "wq.h"
#include "transobj.h"
#include "mlx5_core.h"

#define	netdev_err(dev, ...) \
	if_printf(dev, __VA_ARGS__)

#define	MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE                0x7
#define	MLX5E_PARAMS_DEFAULT_LOG_SQ_SIZE                0xa
#define	MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE                0xd

#define	MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE                0x7
#define	MLX5E_PARAMS_DEFAULT_LOG_RQ_SIZE                0xa
#define	MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE                0xd

#define	MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC      0x10
#define	MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_PKTS      0x20
#define	MLX5E_PARAMS_DEFAULT_TX_CQ_MODERATION_USEC      0x10
#define	MLX5E_PARAMS_DEFAULT_TX_CQ_MODERATION_PKTS      0x20
#define	MLX5E_PARAMS_DEFAULT_MIN_RX_WQES                0x80
#define	MLX5E_PARAMS_DEFAULT_RX_HASH_LOG_TBL_SZ         0x7
#define	MLX5E_CACHELINE_SIZE CACHE_LINE_SIZE
#define	MLX5E_MTU_OVERHEAD \
    (ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN + MLX5E_NET_IP_ALIGN)
#define	MLX5E_MTU_MAX			MIN(0xffff, MJUM16BYTES)

#define	MLX5E_BUDGET_MAX	8192	/* RX and TX */
#define	MLX5E_SQ_BF_BUDGET	16

#define	MLX5E_MAX_TX_NUM_TC	8	/* units */
#define	MLX5E_MAX_TX_HEADER	128	/* bytes */
#define	MLX5E_MAX_TX_MBUF_FRAGS	\
    ((MLX5_SEND_WQE_MAX_WQEBBS * MLX5_SEND_WQEBB_NUM_DS) - \
    (MLX5E_MAX_TX_HEADER / MLX5_SEND_WQE_DS))	/* units */
#define	MLX5E_MAX_TX_INLINE \
  (MLX5E_MAX_TX_HEADER - sizeof(struct mlx5e_tx_wqe) + \
  sizeof(((struct mlx5e_tx_wqe *)0)->eth.inline_hdr_start))	/* bytes */

struct mlx5_core_dev;
struct mlx5e_cq;

typedef void (mlx5e_cq_func_t)(struct mlx5e_cq *);

#define	MLX5E_STATS_COUNT(a,b,c,d) a
#define	MLX5E_STATS_VAR(a,b,c,d) b;
#define	MLX5E_STATS_DESC(a,b,c,d) c, d,

#define	MLX5E_VPORT_STATS(m)						\
  /* HW counters */							\
  m(+1, u64 rx_packets, "rx_packets", "Received packets")		\
  m(+1, u64 rx_bytes, "rx_bytes", "Received bytes")			\
  m(+1, u64 tx_packets, "tx_packets", "Transmitted packets")		\
  m(+1, u64 tx_bytes, "tx_bytes", "Transmitted bytes")			\
  m(+1, u64 rx_error_packets, "rx_error_packets", "Received error packets") \
  m(+1, u64 rx_error_bytes, "rx_error_bytes", "Received error bytes")	\
  m(+1, u64 tx_error_packets, "tx_error_packets", "Transmitted error packets") \
  m(+1, u64 tx_error_bytes, "tx_error_bytes", "Transmitted error bytes") \
  m(+1, u64 rx_unicast_packets, "rx_unicast_packets", "Received unicast packets") \
  m(+1, u64 rx_unicast_bytes, "rx_unicast_bytes", "Received unicast bytes") \
  m(+1, u64 tx_unicast_packets, "tx_unicast_packets", "Transmitted unicast packets") \
  m(+1, u64 tx_unicast_bytes, "tx_unicast_bytes", "Transmitted unicast bytes") \
  m(+1, u64 rx_multicast_packets, "rx_multicast_packets", "Received multicast packets") \
  m(+1, u64 rx_multicast_bytes, "rx_multicast_bytes", "Received multicast bytes") \
  m(+1, u64 tx_multicast_packets, "tx_multicast_packets", "Transmitted multicast packets") \
  m(+1, u64 tx_multicast_bytes, "tx_multicast_bytes", "Transmitted multicast bytes") \
  m(+1, u64 rx_broadcast_packets, "rx_broadcast_packets", "Received broadcast packets") \
  m(+1, u64 rx_broadcast_bytes, "rx_broadcast_bytes", "Received broadcast bytes") \
  m(+1, u64 tx_broadcast_packets, "tx_broadcast_packets", "Transmitted broadcast packets") \
  m(+1, u64 tx_broadcast_bytes, "tx_broadcast_bytes", "Transmitted broadcast bytes") \
  /* SW counters */							\
  m(+1, u64 tso_packets, "tso_packets", "Transmitted TSO packets")	\
  m(+1, u64 tso_bytes, "tso_bytes", "Transmitted TSO bytes")		\
  m(+1, u64 lro_packets, "lro_packets", "Received LRO packets")		\
  m(+1, u64 lro_bytes, "lro_bytes", "Received LRO bytes")		\
  m(+1, u64 rx_csum_good, "rx_csum_good", "Received checksum valid packets") \
  m(+1, u64 rx_csum_none, "rx_csum_none", "Received no checksum packets") \
  m(+1, u64 tx_csum_offload, "tx_csum_offload", "Transmit checksum offload packets") \
  m(+1, u64 tx_queue_stopped, "tx_queue_stopped", "Transmit queue stopped") \
  m(+1, u64 tx_queue_wake, "tx_queue_wake", "Transmit queue wake")	\
  m(+1, u64 tx_queue_dropped, "tx_queue_dropped", "Transmit queue dropped") \
  m(+1, u64 rx_wqe_err, "rx_wqe_err", "Receive WQE errors")

#define	MLX5E_VPORT_STATS_NUM (0 MLX5E_VPORT_STATS(MLX5E_STATS_COUNT))

struct mlx5e_vport_stats {
	struct sysctl_ctx_list ctx;
	u64	arg [0];
	MLX5E_VPORT_STATS(MLX5E_STATS_VAR)
};

#define	MLX5E_PPORT_IEEE802_3_STATS(m)					\
  m(+1, u64 frames_tx, "frames_tx", "Frames transmitted")		\
  m(+1, u64 frames_rx, "frames_rx", "Frames received")			\
  m(+1, u64 check_seq_err, "check_seq_err", "Sequence errors")		\
  m(+1, u64 alignment_err, "alignment_err", "Alignment errors")	\
  m(+1, u64 octets_tx, "octets_tx", "Bytes transmitted")		\
  m(+1, u64 octets_received, "octets_received", "Bytes received")	\
  m(+1, u64 multicast_xmitted, "multicast_xmitted", "Multicast transmitted") \
  m(+1, u64 broadcast_xmitted, "broadcast_xmitted", "Broadcast transmitted") \
  m(+1, u64 multicast_rx, "multicast_rx", "Multicast received")	\
  m(+1, u64 broadcast_rx, "broadcast_rx", "Broadcast received")	\
  m(+1, u64 in_range_len_errors, "in_range_len_errors", "In range length errors") \
  m(+1, u64 out_of_range_len, "out_of_range_len", "Out of range length errors") \
  m(+1, u64 too_long_errors, "too_long_errors", "Too long errors")	\
  m(+1, u64 symbol_err, "symbol_err", "Symbol errors")			\
  m(+1, u64 mac_control_tx, "mac_control_tx", "MAC control transmitted") \
  m(+1, u64 mac_control_rx, "mac_control_rx", "MAC control received")	\
  m(+1, u64 unsupported_op_rx, "unsupported_op_rx", "Unsupported operation received") \
  m(+1, u64 pause_ctrl_rx, "pause_ctrl_rx", "Pause control received")	\
  m(+1, u64 pause_ctrl_tx, "pause_ctrl_tx", "Pause control transmitted")

#define	MLX5E_PPORT_RFC2863_STATS(m)					\
  m(+1, u64 in_octets, "in_octets", "In octets")			\
  m(+1, u64 in_ucast_pkts, "in_ucast_pkts", "In unicast packets")	\
  m(+1, u64 in_discards, "in_discards", "In discards")			\
  m(+1, u64 in_errors, "in_errors", "In errors")			\
  m(+1, u64 in_unknown_protos, "in_unknown_protos", "In unknown protocols") \
  m(+1, u64 out_octets, "out_octets", "Out octets")			\
  m(+1, u64 out_ucast_pkts, "out_ucast_pkts", "Out unicast packets")	\
  m(+1, u64 out_discards, "out_discards", "Out discards")		\
  m(+1, u64 out_errors, "out_errors", "Out errors")			\
  m(+1, u64 in_multicast_pkts, "in_multicast_pkts", "In multicast packets") \
  m(+1, u64 in_broadcast_pkts, "in_broadcast_pkts", "In broadcast packets") \
  m(+1, u64 out_multicast_pkts, "out_multicast_pkts", "Out multicast packets") \
  m(+1, u64 out_broadcast_pkts, "out_broadcast_pkts", "Out broadcast packets")

#define	MLX5E_PPORT_RFC2819_STATS(m)					\
  m(+1, u64 drop_events, "drop_events", "Dropped events")		\
  m(+1, u64 octets, "octets", "Octets")				\
  m(+1, u64 pkts, "pkts", "Packets")					\
  m(+1, u64 broadcast_pkts, "broadcast_pkts", "Broadcast packets")	\
  m(+1, u64 multicast_pkts, "multicast_pkts", "Multicast packets")	\
  m(+1, u64 crc_align_errors, "crc_align_errors", "CRC alignment errors") \
  m(+1, u64 undersize_pkts, "undersize_pkts", "Undersized packets")	\
  m(+1, u64 oversize_pkts, "oversize_pkts", "Oversized packets")	\
  m(+1, u64 fragments, "fragments", "Fragments")			\
  m(+1, u64 jabbers, "jabbers", "Jabbers")				\
  m(+1, u64 collisions, "collisions", "Collisions")			\
  m(+1, u64 p64octets, "p64octets", "Bytes")				\
  m(+1, u64 p65to127octets, "p65to127octets", "Bytes")			\
  m(+1, u64 p128to255octets, "p128to255octets", "Bytes")		\
  m(+1, u64 p256to511octets, "p256to511octets", "Bytes")		\
  m(+1, u64 p512to1023octets, "p512to1023octets", "Bytes")		\
  m(+1, u64 p1024to1518octets, "p1024to1518octets", "Bytes")		\
  m(+1, u64 p1519to2047octets, "p1519to2047octets", "Bytes")		\
  m(+1, u64 p2048to4095octets, "p2048to4095octets", "Bytes")		\
  m(+1, u64 p4096to8191octets, "p4096to8191octets", "Bytes")		\
  m(+1, u64 p8192to10239octets, "p8192to10239octets", "Bytes")

#define	MLX5E_PPORT_STATS(m)			\
  MLX5E_PPORT_IEEE802_3_STATS(m)		\
  MLX5E_PPORT_RFC2863_STATS(m)			\
  MLX5E_PPORT_RFC2819_STATS(m)

#define	MLX5E_PPORT_IEEE802_3_STATS_NUM \
  (0 MLX5E_PPORT_IEEE802_3_STATS(MLX5E_STATS_COUNT))
#define	MLX5E_PPORT_RFC2863_STATS_NUM \
  (0 MLX5E_PPORT_RFC2863_STATS(MLX5E_STATS_COUNT))
#define	MLX5E_PPORT_RFC2819_STATS_NUM \
  (0 MLX5E_PPORT_RFC2819_STATS(MLX5E_STATS_COUNT))
#define	MLX5E_PPORT_STATS_NUM \
  (0 MLX5E_PPORT_STATS(MLX5E_STATS_COUNT))

struct mlx5e_pport_stats {
	struct sysctl_ctx_list ctx;
	u64	arg [0];
	MLX5E_PPORT_STATS(MLX5E_STATS_VAR)
};

#define	MLX5E_RQ_STATS(m)					\
  m(+1, u64 packets, "packets", "Received packets")		\
  m(+1, u64 csum_none, "csum_none", "Received packets")		\
  m(+1, u64 lro_packets, "lro_packets", "Received packets")	\
  m(+1, u64 lro_bytes, "lro_bytes", "Received packets")		\
  m(+1, u64 wqe_err, "wqe_err", "Received packets")

#define	MLX5E_RQ_STATS_NUM (0 MLX5E_RQ_STATS(MLX5E_STATS_COUNT))

struct mlx5e_rq_stats {
	struct sysctl_ctx_list ctx;
	u64	arg [0];
	MLX5E_RQ_STATS(MLX5E_STATS_VAR)
};

#define	MLX5E_RX_MBUF_DMA_ADDR(_mb) \
	(_mb)->m_pkthdr.PH_loc.sixtyfour[0]

#define	MLX5E_SQ_STATS(m)						\
  m(+1, u64 packets, "packets", "Received packets")			\
  m(+1, u64 tso_packets, "tso_packets", "Received packets")		\
  m(+1, u64 tso_bytes, "tso_bytes", "Received packets")			\
  m(+1, u64 csum_offload_none, "csum_offload_none", "Received packets")	\
  m(+1, u64 stopped, "stopped", "Received packets")			\
  m(+1, u64 wake, "wake", "Received packets")				\
  m(+1, u64 dropped, "dropped", "Received packets")			\
  m(+1, u64 nop, "nop", "Received packets")

#define	MLX5E_SQ_STATS_NUM (0 MLX5E_SQ_STATS(MLX5E_STATS_COUNT))

struct mlx5e_sq_stats {
	struct sysctl_ctx_list ctx;
	u64	arg [0];
	MLX5E_SQ_STATS(MLX5E_STATS_VAR)
};

struct mlx5e_stats {
	struct mlx5e_vport_stats vport;
	struct mlx5e_pport_stats pport;
};

struct mlx5e_params {
	u8	log_sq_size;
	u8	log_rq_size;
	u16	num_channels;
	u8	default_vlan_prio;
	u8	num_tc;
	u16	rx_cq_moderation_usec;
	u16	rx_cq_moderation_pkts;
	u16	tx_cq_moderation_usec;
	u16	tx_cq_moderation_pkts;
	u16	min_rx_wqes;
	u16	rx_hash_log_tbl_sz;
};

#define	MLX5E_PARAMS(m)							\
  m(+1, u64 tx_queue_size_max, "tx_queue_size_max", "Max send queue size") \
  m(+1, u64 rx_queue_size_max, "rx_queue_size_max", "Max receive queue size") \
  m(+1, u64 tx_queue_size, "tx_queue_size", "Default send queue size")	\
  m(+1, u64 rx_queue_size, "rx_queue_size", "Default receive queue size") \
  m(+1, u64 channels, "channels", "Default number of channels")		\
  m(+1, u64 coalesce_usecs_max, "coalesce_usecs_max", "Maximum usecs for joining packets") \
  m(+1, u64 coalesce_pkts_max, "coalesce_pkts_max", "Maximum packets to join") \
  m(+1, u64 rx_coalesce_usecs, "rx_coalesce_usecs", "Limit in usec for joining rx packets") \
  m(+1, u64 rx_coalesce_pkts, "rx_coalesce_pkts", "Maximum number of rx packets to join") \
  m(+1, u64 tx_coalesce_usecs, "tx_coalesce_usecs", "Limit in usec for joining tx packets") \
  m(+1, u64 tx_coalesce_pkts, "tx_coalesce_pkts", "Maximum number of tx packets to join")

#define	MLX5E_PARAMS_NUM (0 MLX5E_PARAMS(MLX5E_STATS_COUNT))

struct mlx5e_params_ethtool {
	u64	arg [0];
	MLX5E_PARAMS(MLX5E_STATS_VAR)
};

struct mlx5e_cq {
	/* data path - accessed per cqe */
	struct mlx5_cqwq wq;
	mlx5e_cq_func_t *func;

	/* data path - accessed per HW polling */
	struct mlx5_core_cq mcq;
	struct mlx5e_channel *channel;

	/* control */
	struct mlx5_wq_ctrl wq_ctrl;
} __aligned(MLX5E_CACHELINE_SIZE);

struct mlx5e_rq {
	/* data path */
	struct mlx5_wq_ll wq;
	spinlock_t lock;
	u32	wqe_sz;
	struct mbuf **mbuf;

	struct device *pdev;
	struct net_device *netdev;
	struct mlx5e_rq_stats stats;
	struct mlx5e_cq cq;
#ifdef HAVE_TURBO_LRO
	struct tlro_ctrl lro;
#else
	struct lro_ctrl lro;
#endif
	volatile int enabled;
	int	ix;

	/* control */
	struct mlx5_wq_ctrl wq_ctrl;
	u32	rqn;
	struct mlx5e_channel *channel;
} __aligned(MLX5E_CACHELINE_SIZE);

struct mlx5e_tx_mbuf_cb {
	u32	num_bytes;
	u8	num_wqebbs;
	u8	num_dma;
};

#define	MLX5E_TX_MBUF_CB(_mb) \
    ((struct mlx5e_tx_mbuf_cb *)(_mb)->m_pkthdr.PH_loc.sixtyfour)

struct mlx5e_sq_dma {
	dma_addr_t addr;
	u32	size;
};

enum {
	MLX5E_SQ_STATE_WAKE_TXQ_ENABLE,
};

struct mlx5e_sq {
	/* data path */
	spinlock_t lock;

	/* dirtied @completion */
	u16	cc;
	u32	dma_fifo_cc;

	/* dirtied @xmit */
	u32	dma_fifo_pc __aligned(MLX5E_CACHELINE_SIZE);
	u16	pc;
	u16	bf_offset;
	struct mlx5e_sq_stats stats;

	struct mlx5e_cq cq;

	/* pointers to per packet info: write@xmit, read@completion */
	struct mbuf **mbuf;
	struct mlx5e_sq_dma *dma_fifo;

	/* read only */
	struct mlx5_wq_cyc wq;
	u32	dma_fifo_mask;
	void __iomem *uar_map;
	void __iomem *uar_bf_map;
	u32	sqn;
	u32	bf_buf_size;
	struct device *pdev;
	u32	mkey_be;
	unsigned long state;

	/* control path */
	struct mlx5_wq_ctrl wq_ctrl;
	struct mlx5_uar uar;
	struct mlx5e_channel *channel;
	int	tc;
} __aligned(MLX5E_CACHELINE_SIZE);

static inline bool
mlx5e_sq_has_room_for(struct mlx5e_sq *sq, u16 n)
{
	return ((sq->wq.sz_m1 & (sq->cc - sq->pc)) >= n ||
	    sq->cc == sq->pc);
}

struct mlx5e_channel {
	/* data path */
	struct mlx5e_rq rq;
	struct mlx5e_sq sq[MLX5E_MAX_TX_NUM_TC];
	struct device *pdev;
	struct net_device *netdev;
	u32	mkey_be;
	u8	num_tc;

	/* control */
	struct mlx5e_priv *priv;
	int	ix;
	int	cpu;
} __aligned(MLX5E_CACHELINE_SIZE);

enum mlx5e_traffic_types {
	MLX5E_TT_IPV4_TCP,
	MLX5E_TT_IPV6_TCP,
	MLX5E_TT_IPV4_UDP,
	MLX5E_TT_IPV6_UDP,
	MLX5E_TT_IPV4_IPSEC_AH,
	MLX5E_TT_IPV6_IPSEC_AH,
	MLX5E_TT_IPV4_IPSEC_ESP,
	MLX5E_TT_IPV6_IPSEC_ESP,
	MLX5E_TT_IPV4,
	MLX5E_TT_IPV6,
	MLX5E_TT_ANY,
	MLX5E_NUM_TT,
};

enum {
	MLX5E_RQT_SPREADING = 0,
	MLX5E_RQT_DEFAULT_RQ = 1,
	MLX5E_NUM_RQT = 2,
};

struct mlx5e_eth_addr_info {
	u8	addr [ETH_ALEN + 2];
	u32	tt_vec;
	u32	ft_ix[MLX5E_NUM_TT];	/* flow table index per traffic type */
};

#define	MLX5E_ETH_ADDR_HASH_SIZE (1 << BITS_PER_BYTE)

struct mlx5e_eth_addr_hash_node;

struct mlx5e_eth_addr_hash_head {
	struct mlx5e_eth_addr_hash_node *lh_first;
};

struct mlx5e_eth_addr_db {
	struct mlx5e_eth_addr_hash_head netdev_uc[MLX5E_ETH_ADDR_HASH_SIZE];
	struct mlx5e_eth_addr_hash_head netdev_mc[MLX5E_ETH_ADDR_HASH_SIZE];
	struct mlx5e_eth_addr_info broadcast;
	struct mlx5e_eth_addr_info allmulti;
	struct mlx5e_eth_addr_info promisc;
	bool	broadcast_enabled;
	bool	allmulti_enabled;
	bool	promisc_enabled;
};

enum {
	MLX5E_STATE_ASYNC_EVENTS_ENABLE,
	MLX5E_STATE_OPENED,
};

struct mlx5e_vlan_db {
	unsigned long active_vlans[BITS_TO_LONGS(VLAN_N_VID)];
	u32	active_vlans_ft_ix[VLAN_N_VID];
	u32	untagged_rule_ft_ix;
	u32	any_vlan_rule_ft_ix;
	bool	filter_disabled;
};

struct mlx5e_flow_table {
	void   *vlan;
	void   *main;
};

struct mlx5e_priv {
	/* priv data path fields - start */
	int	order_base_2_num_channels;
	int	queue_mapping_channel_mask;
	int	num_tc;
	int	default_vlan_prio;
	/* priv data path fields - end */

	unsigned long state;
	struct mutex state_lock;	/* Protects Interface state */
	struct mlx5_uar cq_uar;
	u32	pdn;
	struct mlx5_core_mr mr;

	struct mlx5e_channel * volatile *channel;
	u32	tisn[MLX5E_MAX_TX_NUM_TC];
	u32	rqtn;
	u32	tirn[MLX5E_NUM_TT];

	struct mlx5e_flow_table ft;
	struct mlx5e_eth_addr_db eth_addr;
	struct mlx5e_vlan_db vlan;

	struct mlx5e_params params;
	struct mlx5e_params_ethtool params_ethtool;
	spinlock_t async_events_spinlock;	/* sync hw events */
	struct work_struct update_stats_work;
	struct work_struct update_carrier_work;
	struct work_struct set_rx_mode_work;

	struct mlx5_core_dev *mdev;
	struct net_device *netdev;
	struct sysctl_ctx_list sysctl_ctx;
	struct sysctl_oid *sysctl;
	struct mlx5e_stats stats;

	eventhandler_tag vlan_detach;
	eventhandler_tag vlan_attach;
	struct ifmedia media;
	int	media_status_last;
	int	media_active_last;
	int	media_active_user;

	struct timer_list watchdog;
};

#define	MLX5E_NET_IP_ALIGN 2

struct mlx5e_tx_wqe {
	struct mlx5_wqe_ctrl_seg ctrl;
	struct mlx5_wqe_eth_seg eth;
};

struct mlx5e_rx_wqe {
	struct mlx5_wqe_srq_next_seg next;
	struct mlx5_wqe_data_seg data;
};

enum mlx5e_link_mode {
	MLX5E_1000BASE_CX_SGMII = 0,
	MLX5E_1000BASE_KX = 1,
	MLX5E_10GBASE_CX4 = 2,
	MLX5E_10GBASE_KX4 = 3,
	MLX5E_10GBASE_KR = 4,
	MLX5E_20GBASE_KR2 = 5,
	MLX5E_40GBASE_CR4 = 6,
	MLX5E_40GBASE_KR4 = 7,
	MLX5E_56GBASE_R4 = 8,
	MLX5E_10GBASE_CR = 12,
	MLX5E_10GBASE_SR = 13,
	MLX5E_10GBASE_ER = 14,
	MLX5E_40GBASE_SR4 = 15,
	MLX5E_40GBASE_LR4 = 16,
	MLX5E_100GBASE_CR4 = 20,
	MLX5E_100GBASE_SR4 = 21,
	MLX5E_100GBASE_KR4 = 22,
	MLX5E_100GBASE_LR4 = 23,
	MLX5E_100BASE_TX = 24,
	MLX5E_100BASE_T = 25,
	MLX5E_10GBASE_T = 26,
	MLX5E_25GBASE_CR = 27,
	MLX5E_25GBASE_KR = 28,
	MLX5E_25GBASE_SR = 29,
	MLX5E_50GBASE_CR2 = 30,
	MLX5E_50GBASE_KR2 = 31,
	MLX5E_LINK_MODES_NUMBER,
};

#define	MLX5E_PROT_MASK(link_mode) (1 << (link_mode))
#define	MLX5E_FLD_MAX(typ, fld) ((1ULL << __mlx5_bit_sz(typ, fld)) - 1ULL)

int	mlx5e_xmit(struct net_device *dev, struct mbuf *mb);

int	mlx5e_open_locked(struct net_device *);
int	mlx5e_close_locked(struct net_device *);

void	mlx5e_completion_event(struct mlx5_core_cq *mcq);
void	mlx5e_cq_error_event(struct mlx5_core_cq *mcq, enum mlx5_event event);
void	mlx5e_rx_cq_function(struct mlx5e_cq *);
void	mlx5e_tx_cq_function(struct mlx5e_cq *);
struct mlx5_cqe64 *mlx5e_get_cqe(struct mlx5e_cq *cq);

int	mlx5e_open_flow_table(struct mlx5e_priv *priv);
void	mlx5e_close_flow_table(struct mlx5e_priv *priv);
void	mlx5e_set_rx_mode_core(struct mlx5e_priv *priv);
void	mlx5e_set_rx_mode_work(struct work_struct *work);

void	mlx5e_vlan_rx_add_vid(void *arg, struct net_device *dev, u16 vid);
void	mlx5e_vlan_rx_kill_vid(void *arg, struct net_device *dev, u16 vid);
void	mlx5e_enable_vlan_filter(struct mlx5e_priv *priv);
void	mlx5e_disable_vlan_filter(struct mlx5e_priv *priv);
int	mlx5e_add_all_vlan_rules(struct mlx5e_priv *priv);
void	mlx5e_del_all_vlan_rules(struct mlx5e_priv *priv);

static inline void
mlx5e_tx_notify_hw(struct mlx5e_sq *sq,
    struct mlx5e_tx_wqe *wqe, int bf_sz)
{
	u16 ofst = MLX5_BF_OFFSET + sq->bf_offset;

	/* ensure wqe is visible to device before updating doorbell record */
	wmb();

	*sq->wq.db = cpu_to_be32(sq->pc);

	/*
	 * Ensure the doorbell record is visible to device before ringing
	 * the doorbell:
	 */
	wmb();

	if (bf_sz) {
		__iowrite64_copy(sq->uar_bf_map + ofst, &wqe->ctrl, bf_sz);

		/* flush the write-combining mapped buffer */
		wmb();

	} else {
		mlx5_write64((__be32 *)&wqe->ctrl, sq->uar_map + ofst, NULL);
	}

	sq->bf_offset ^= sq->bf_buf_size;
}

static inline void
mlx5e_cq_arm(struct mlx5e_cq *cq)
{
	struct mlx5_core_cq *mcq;

	mcq = &cq->mcq;
	mlx5_cq_arm(mcq, MLX5_CQ_DB_REQ_NOT, mcq->uar->map, NULL, cq->wq.cc);
}

extern const struct ethtool_ops mlx5e_ethtool_ops;
void	mlx5e_create_ethtool(struct mlx5e_priv *);
void	mlx5e_create_stats(struct sysctl_ctx_list *,
    struct sysctl_oid_list *, const char *,
    const char **, unsigned, u64 *);
void	mlx5e_send_nop(struct mlx5e_sq *, bool);

#endif					/* _MLX5_EN_H_ */
