# MIT License
#
# Copyright (c) 2019-2021 Ecole Polytechnique Federale Lausanne (EPFL)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

ROOTDIR=$(shell git rev-parse --show-toplevel)
RTE_SDK=$(ROOTDIR)/dpdk
R2P2LIB_DIR=$(ROOTDIR)/r2p2
RAFT_DIR=$(shell git rev-parse --show-toplevel)/../raft

include $(ROOTDIR)/netstack/dp/dir.mk
include $(ROOTDIR)/netstack/net/dir.mk
include $(R2P2LIB_DIR)/dir.mk


CC=gcc
CFLAGS += -g -O3 -I$(ROOTDIR)/netstack/inc -I$(R2P2LIB_DIR)/inc -I$(RTE_SDK)/x86_64-native-linuxapp-gcc/include -I$(RAFT_DIR)/include -DNO_BATCH #-DACCELERATED #-DRAFT_STATS

ifeq ($(WITH_RAFT), 1)
	CFLAGS += -DWITH_RAFT
endif

ifeq ($(LB_REPLIES), 1)
	CFLAGS += -DLB_REPLIES
endif

ifeq ($(SKIP_NO_SE), 1)
	CFLAGS += -DSKIP_NO_SE
endif

ifeq ($(ACCELERATED), 1)
	CFLAGS += -DACCELERATED
endif

ifeq ($(SWITCH_AGG), 1)
	CFLAGS += -DSWITCH_AGG
endif

ifeq ($(SMART_LB), 1)
	CFLAGS += -DSMART_LB
endif

ifeq ($(VIEW_CHANGE_EXP), 1)
    CFLAGS += -DVIEW_CHANGE_EXP
endif

ifdef PACKET_LOSS
	CFLAGS += -DPACKET_LOSS=$(PACKET_LOSS)
endif

WERROR_FLAGS := -W -Wall -Wstrict-prototypes -Wmissing-prototypes
WERROR_FLAGS += -Wmissing-declarations -Wold-style-definition -Wpointer-arith
WERROR_FLAGS += -Wcast-align -Wnested-externs -Wcast-qual
WERROR_FLAGS += -Wformat-nonliteral -Wformat-security
WERROR_FLAGS += -Wundef -Wwrite-strings

CFLAGS += $(WERROR_FLAGS) -mavx2
LDFLAGS= -Wl,--whole-archive -Wl,-ldpdk -Wl,--no-whole-archive -lrt -lpthread -lm -ldl -L$(RTE_SDK)/x86_64-native-linuxapp-gcc/lib -lconfig -lnuma -lgcov --coverage -lpcap

SRCS_C := $(addprefix $(ROOTDIR)/netstack/dp/, $(DP_SRC)) $(addprefix $(ROOTDIR)/netstack/net/, $(NET_SRC)) $(addprefix $(R2P2LIB_DIR)/, $(R2P2_SRC_C))
OBJS_C := $(patsubst %.c, %.o, $(SRCS_C))

ifeq ($(WITH_RAFT), 1)
	OBJS_C += $(RAFT_DIR)/libraft.a
endif

all:
	make r2p2-echo
	make r2p2-echo-fdir
	make synthetic-time
	make synthetic-time-fdir
	make r2p2-router
	make udp-echo
	make udp-synthetic

debug: cleanstate debug.o $(OBJS_C)
	$(CC) -o $@ debug.o $(OBJS_C) $(LDFLAGS)

r2p2-echo: cleanstate r2p2-echo.o $(OBJS_C)
	$(CC) -o $@ r2p2-echo.o $(OBJS_C) $(LDFLAGS)

r2p2-echo-fdir: CFLAGS += -DFDIR
r2p2-echo-fdir: cleanstate r2p2-echo.o $(OBJS_C)
	$(CC) -o $@ r2p2-echo.o $(OBJS_C) $(LDFLAGS)

stss: cleanstate r2p2-stss.o $(OBJS_C)
	$(CC) -o $@ r2p2-stss.o $(OBJS_C) $(LDFLAGS)

synthetic-size: cleanstate r2p2-synthetic-size.o $(OBJS_C)
	$(CC) -o $@ r2p2-synthetic-size.o $(OBJS_C) $(LDFLAGS)

synthetic-time: cleanstate r2p2-synthetic-time.o $(OBJS_C)
	$(CC) -o $@ r2p2-synthetic-time.o $(OBJS_C) $(LDFLAGS)

synthetic-time-fdir: CFLAGS += -DFDIR
synthetic-time-fdir: cleanstate r2p2-synthetic-time.o $(OBJS_C)
	$(CC) -o $@ r2p2-synthetic-time.o $(OBJS_C) $(LDFLAGS)

r2p2-router: CFLAGS += -DROUTER
r2p2-router: cleanstate r2p2-router.o $(OBJS_C)
	$(CC) -o $@ r2p2-router.o $(OBJS_C) $(LDFLAGS)

udp-echo: cleanstate udp-echo.o $(OBJS_C)
	$(CC) -o $@ udp-echo.o $(OBJS_C) $(LDFLAGS)

udp-synthetic: cleanstate udp-synthetic.o $(OBJS_C)
	$(CC) -o $@ udp-synthetic.o $(OBJS_C) $(LDFLAGS)

cleanstate:
	make -C $(R2P2LIB_DIR) clean
	make clean
	rm -f $(ROOTDIR)/netstack/net/*.o
	rm -f $(ROOTDIR)/netstack/dp/*.o

clean:
	rm -f *.o

distclean:
	make clean
	rm -f synthetic-time-fdir synthetic-time r2p2-router udp-echo
