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

struct mlx5_cqe64 *
mlx5e_get_cqe(struct mlx5e_cq *cq)
{
	struct mlx5_cqe64 *cqe;

	cqe = mlx5_cqwq_get_wqe(&cq->wq, mlx5_cqwq_get_ci(&cq->wq));

	if ((cqe->op_own ^ mlx5_cqwq_get_wrap_cnt(&cq->wq)) & MLX5_CQE_OWNER_MASK)
		return (NULL);

	mlx5_cqwq_pop(&cq->wq);

	/* ensure cqe content is read after cqe ownership bit */
	rmb();

	return (cqe);
}

void
mlx5e_completion_event(struct mlx5_core_cq *mcq)
{
	struct mlx5e_cq *cq = container_of(mcq, struct mlx5e_cq, mcq);
	/* process event */
	cq->func(cq);
}

void
mlx5e_cq_error_event(struct mlx5_core_cq *mcq, enum mlx5_event event)
{
	struct mlx5e_cq *cq = container_of(mcq, struct mlx5e_cq, mcq);
	struct mlx5e_channel *c = cq->channel;
	struct mlx5e_priv *priv = c->priv;
	struct net_device *netdev = priv->netdev;

	netdev_err(netdev, "%s: cqn=0x%.6x event=0x%.2x\n",
	    __func__, mcq->cqn, event);
}
