MLXDIR?=${.CURDIR}/../../drivex/mlx5/generated/freebsd

.PATH:  ${MLXDIR}/ib

SRCS= \
mlx5_ah.c \
mlx5_cq.c \
mlx5_doorbell.c \
mlx5_mad.c \
mlx5_main.c \
mlx5_mem.c \
mlx5_mr.c \
mlx5_qp.c \
mlx5_roce.c \
mlx5_srq.c \
device_if.h bus_if.h vnode_if.h pci_if.h \
        opt_inet.h opt_inet6.h

CFLAGS+= -I${SYSDIR}/ofed/include
CFLAGS+= -I${MLXDIR}/ib
CFLAGS+= -I${MLXDIR}/core
CFLAGS+= -DDX_FREEBSD

KMOD=mlx5ib

.include <bsd.kmod.mk>

CFLAGS+= -Wno-cast-qual -Wno-pointer-arith ${GCC_MS_EXTENSIONS}
