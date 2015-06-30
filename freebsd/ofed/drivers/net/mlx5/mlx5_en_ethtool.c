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

static int
mlx5e_ethtool_handler(SYSCTL_HANDLER_ARGS)
{
	struct mlx5e_priv *priv = arg1;
	int was_opened;
	int error;

	mutex_lock(&priv->state_lock);
	error = sysctl_handle_64(oidp,
	    priv->params_ethtool.arg + arg2, 0, req);
	if (error || req->newptr == NULL)
		goto done;

	was_opened = test_bit(MLX5E_STATE_OPENED, &priv->state);
	if (was_opened)
		mlx5e_close_locked(priv->ifp);

	/* import TX queue size */
	if (priv->params_ethtool.tx_queue_size <
	    (1 << MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE)) {
		priv->params_ethtool.tx_queue_size =
		    (1 << MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE);
	} else if (priv->params_ethtool.tx_queue_size >
	    priv->params_ethtool.tx_queue_size_max) {
		priv->params_ethtool.tx_queue_size =
		    priv->params_ethtool.tx_queue_size_max;
	}
	priv->params.log_sq_size =
	    order_base_2(priv->params_ethtool.tx_queue_size);

	/* import RX queue size */
	if (priv->params_ethtool.rx_queue_size <
	    (1 << MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE)) {
		priv->params_ethtool.rx_queue_size =
		    (1 << MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE);
	} else if (priv->params_ethtool.rx_queue_size >
	    priv->params_ethtool.rx_queue_size_max) {
		priv->params_ethtool.rx_queue_size =
		    priv->params_ethtool.rx_queue_size_max;
	}
	priv->params.log_rq_size =
	    order_base_2(priv->params_ethtool.rx_queue_size);

	priv->params.min_rx_wqes = min_t (u16,
	          priv->params_ethtool.rx_queue_size - 1,
	          MLX5E_PARAMS_DEFAULT_MIN_RX_WQES);

	/* import number of channels */
	if (priv->params_ethtool.channels < 1)
		priv->params_ethtool.channels = 1;
	else if (priv->params_ethtool.channels >
	    (u64) priv->mdev->priv.eq_table.num_comp_vectors) {
		priv->params_ethtool.channels =
		    (u64) priv->mdev->priv.eq_table.num_comp_vectors;
	}
	priv->params.num_channels = priv->params_ethtool.channels;

	/* import RX coal time */
	if (priv->params_ethtool.rx_coalesce_usecs < 1)
		priv->params_ethtool.rx_coalesce_usecs = 0;
	else if (priv->params_ethtool.rx_coalesce_usecs >
	    MLX5E_FLD_MAX(cqc, cq_period)) {
		priv->params_ethtool.rx_coalesce_usecs =
		    MLX5E_FLD_MAX(cqc, cq_period);
	}
	priv->params.rx_cq_moderation_usec = priv->params_ethtool.rx_coalesce_usecs;

	/* import RX coal pkts */
	if (priv->params_ethtool.rx_coalesce_pkts < 1)
		priv->params_ethtool.rx_coalesce_pkts = 0;
	else if (priv->params_ethtool.rx_coalesce_pkts >
	    MLX5E_FLD_MAX(cqc, cq_max_count)) {
		priv->params_ethtool.rx_coalesce_pkts =
		    MLX5E_FLD_MAX(cqc, cq_max_count);
	}
	priv->params.rx_cq_moderation_pkts = priv->params_ethtool.rx_coalesce_pkts;

	/* import TX coal time */
	if (priv->params_ethtool.tx_coalesce_usecs < 1)
		priv->params_ethtool.tx_coalesce_usecs = 0;
	else if (priv->params_ethtool.tx_coalesce_usecs >
	    MLX5E_FLD_MAX(cqc, cq_period)) {
		priv->params_ethtool.tx_coalesce_usecs =
		    MLX5E_FLD_MAX(cqc, cq_period);
	}
	priv->params.tx_cq_moderation_usec = priv->params_ethtool.tx_coalesce_usecs;

	/* import TX coal pkts */
	if (priv->params_ethtool.tx_coalesce_pkts < 1)
		priv->params_ethtool.tx_coalesce_pkts = 0;
	else if (priv->params_ethtool.tx_coalesce_pkts >
	    MLX5E_FLD_MAX(cqc, cq_max_count)) {
		priv->params_ethtool.tx_coalesce_pkts = MLX5E_FLD_MAX(cqc, cq_max_count);
	}
	priv->params.tx_cq_moderation_pkts = priv->params_ethtool.tx_coalesce_pkts;

	if (was_opened)
		mlx5e_open_locked(priv->ifp);
done:
	mutex_unlock(&priv->state_lock);
	return (error);
}

static const char *mlx5e_params_desc[] = {
	MLX5E_PARAMS(MLX5E_STATS_DESC)
};

void
mlx5e_create_ethtool(struct mlx5e_priv *priv)
{
	struct sysctl_oid *node;
	const char *pnameunit;
	unsigned x;

	/* set some defaults */
	priv->params_ethtool.tx_queue_size_max = 1 << MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE;
	priv->params_ethtool.rx_queue_size_max = 1 << MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE;
	priv->params_ethtool.tx_queue_size = 1 << priv->params.log_sq_size;
	priv->params_ethtool.rx_queue_size = 1 << priv->params.log_rq_size;
	priv->params_ethtool.channels = priv->params.num_channels;
	priv->params_ethtool.coalesce_pkts_max = MLX5E_FLD_MAX(cqc, cq_max_count);
	priv->params_ethtool.coalesce_usecs_max = MLX5E_FLD_MAX(cqc, cq_period);
	priv->params_ethtool.rx_coalesce_usecs = priv->params.rx_cq_moderation_usec;
	priv->params_ethtool.rx_coalesce_pkts = priv->params.rx_cq_moderation_pkts;
	priv->params_ethtool.tx_coalesce_usecs = priv->params.tx_cq_moderation_usec;
	priv->params_ethtool.tx_coalesce_pkts = priv->params.tx_cq_moderation_pkts;

	/* create root node */
	node = SYSCTL_ADD_NODE(&priv->sysctl_ctx,
	    SYSCTL_CHILDREN(priv->sysctl), OID_AUTO,
	    "conf", CTLFLAG_RW, NULL, "Configuration");
	if (node == NULL)
		return;
	for (x = 0; x != MLX5E_PARAMS_NUM; x++) {
		/* check for read-only parameter */
		if (strstr(mlx5e_params_desc[2 * x], "_max") != NULL) {
			SYSCTL_ADD_PROC(&priv->sysctl_ctx, SYSCTL_CHILDREN(node), OID_AUTO,
			    mlx5e_params_desc[2 * x], CTLTYPE_U64 | CTLFLAG_RD |
			    CTLFLAG_MPSAFE, priv, x, &mlx5e_ethtool_handler, "QU",
			    mlx5e_params_desc[2 * x + 1]);
		} else {
			SYSCTL_ADD_PROC(&priv->sysctl_ctx, SYSCTL_CHILDREN(node), OID_AUTO,
			    mlx5e_params_desc[2 * x], CTLTYPE_U64 | CTLFLAG_RWTUN |
			    CTLFLAG_MPSAFE, priv, x, &mlx5e_ethtool_handler, "QU",
			    mlx5e_params_desc[2 * x + 1]);
		}
	}

	pnameunit = device_get_nameunit(priv->mdev->pdev->dev.bsddev);

	SYSCTL_ADD_STRING(&priv->sysctl_ctx, SYSCTL_CHILDREN(node),
	    OID_AUTO, "device_name", CTLFLAG_RD,
	    __DECONST(void *, pnameunit), 0,
	    "PCI device name");
}

void
mlx5e_create_stats(struct sysctl_ctx_list *ctx,
    struct sysctl_oid_list *parent, const char *buffer,
    const char **desc, unsigned num, u64 * arg)
{
	struct sysctl_oid *node;
	unsigned x;

	sysctl_ctx_init(ctx);

	node = SYSCTL_ADD_NODE(ctx, parent, OID_AUTO,
	    buffer, CTLFLAG_RD, NULL, "Statistics");
	if (node == NULL)
		return;
	for (x = 0; x != num; x++) {
		SYSCTL_ADD_UQUAD(ctx, SYSCTL_CHILDREN(node), OID_AUTO,
		    desc[2 * x], CTLFLAG_RD, arg + x, desc[2 * x + 1]);
	}
}
