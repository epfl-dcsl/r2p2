R2P2_SRC_C = r2p2-common.c mempool.c cfg.c
LINUX_SRC_C = linux-backend.c

ifeq ($(WITH_RAFT), 1)
	R2P2_SRC_C += hovercraft.c hovercraft-log.c hovercraft-stats.c
endif

ifeq ($(WITH_TIMESTAMPING), 1)
	LINUX_SRC_C += timestamping.c
endif
