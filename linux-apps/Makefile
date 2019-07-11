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
R2P2LIB_DIR=$(ROOTDIR)/r2p2

include $(R2P2LIB_DIR)/dir.mk

CFLAGS= -Wall -g -MD -O3 -I./../r2p2/inc -DLINUX
LDFLAGS= -lm -lpthread -lconfig

ifeq ($(WITH_TIMESTAMPING), 1)
	EXTRA_CLIENT_FLAGS = -DWITH_TIMESTAMPING
endif

ifeq ($(WITH_ROUTER), 1)
	EXTRA_SERVER_FLAGS = -DWITH_ROUTER
endif

SRC_C :=$(addprefix $(R2P2LIB_DIR)/, $(R2P2_SRC_C)) $(addprefix $(R2P2LIB_DIR)/, $(LINUX_SRC_C))
OBJC=$(patsubst %.c,%.o,$(SRC_C))

all:
	make linux_client
	make linux_server


linux_client: CFLAGS += $(EXTRA_CLIENT_FLAGS)
linux_client: cleanstate linux-client.o $(OBJC)
	gcc -o $@ linux-client.o $(OBJC)  $(LDFLAGS)

linux_server: CFLAGS += $(EXTRA_SERVER_FLAGS)
linux_server: cleanstate linux-server.o $(OBJC)
	gcc -o $@ linux-server.o $(OBJC) $(LDFLAGS)

cleanstate:
	make -C ../r2p2 clean

clean:
	rm -f *.o *.d

distclean:
	make clean
	rm -f linux_client linux_server
