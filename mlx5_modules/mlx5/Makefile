MLXDIR?=${.CURDIR}/../../drivex/mlx5/generated/freebsd

.PATH:	${MLXDIR}/core

SRCS= \
mlx5_alloc.c \
mlx5_cmd.c \
mlx5_cq.c \
mlx5_eq.c \
mlx5_flow_table.c \
mlx5_fw.c \
mlx5_health.c \
mlx5_mad.c \
mlx5_main.c \
mlx5_mcg.c \
mlx5_mr.c \
mlx5_pagealloc.c \
mlx5_pd.c \
mlx5_port.c \
mlx5_qp.c \
mlx5_srq.c \
mlx5_transobj.c \
mlx5_uar.c \
mlx5_vport.c \
mlx5_wq.c \
device_if.h bus_if.h vnode_if.h pci_if.h \
        opt_inet.h opt_inet6.h

CFLAGS+= -I${SYSDIR}/ofed/include
CFLAGS+= -I${MLXDIR}/core
CFLAGS+= -I${.CURDIR}
CFLAGS+= -DDX_FREEBSD

KMOD=mlx5

.include <bsd.kmod.mk>

CFLAGS+= -Wno-cast-qual -Wno-pointer-arith ${GCC_MS_EXTENSIONS}

