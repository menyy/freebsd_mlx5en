MLXDIR?=${.CURDIR}/../../../drivex/mlx5/generated/freebsd

.PATH:	${MLXDIR}/core ${.CURDIR}/../../ofed/drivers/net/mlx5

SRCS= \
mlx5_en_ethtool.c \
mlx5_en_main.c \
mlx5_en_tx.c \
mlx5_en_flow_table.c \
mlx5_en_rx.c \
mlx5_en_txrx.c \
device_if.h bus_if.h vnode_if.h pci_if.h \
        opt_inet.h opt_inet6.h

.if defined(HAVE_TURBO_LRO)
CFLAGS+= -DHAVE_TURBO_LRO
SRCS+= tcp_tlro.c
.endif

CFLAGS+= -I${SYSDIR}/ofed/include
CFLAGS+= -I${MLXDIR}/core
CFLAGS+= -I${.CURDIR}
CFLAGS+= -DDX_FREEBSD

KMOD=mlx5en

.include <bsd.kmod.mk>

CFLAGS+= -Wno-cast-qual -Wno-pointer-arith ${GCC_MS_EXTENSIONS}

