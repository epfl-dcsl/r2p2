R2P2_SRC_C = r2p2-common.c mempool.c cfg.c
LINUX_SRC_C = linux-backend.c

ifeq ($(WITH_TIMESTAMPING), 1)
	LINUX_SRC_C += timestamping.c
endif
