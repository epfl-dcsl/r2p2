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

TARGETS := lucenerrpp

all: $(TARGETS)

ROOTDIR=$(shell git rev-parse --show-toplevel)
R2P2LIB_DIR=$(ROOTDIR)/r2p2

include $(R2P2LIB_DIR)/dir.mk

SRC_DIR_LUCENE := ./lucene
SRCS_LUCENE := $(wildcard $(SRC_DIR_LUCENE)/*.cpp)
LUCENEOFILES=$(patsubst %.cpp,%.o,$(SRCS_LUCENE))
SRCS_R2P2 :=$(addprefix $(R2P2LIB_DIR)/, $(R2P2_SRC_C)) $(addprefix $(R2P2LIB_DIR)/, $(LINUX_SRC_C))
R2P2OFILES=$(patsubst %.c,%.o,$(SRCS_R2P2))
CXXFLAGS += -I./inc/lucene++ -I$(R2P2LIB_DIR)/inc -g -std=c++14 -O3 -DLINUX
CFLAGS += -I./inc/lucene++ -I$(R2P2LIB_DIR)/inc -g -O3 -DLINUX

LLUCE := -L./shared -rdynamic -llucene++ -lboost_system -lpthread -lboost_date_time -lboost_filesystem -lboost_iostreams -lboost_regex -lboost_system -lboost_thread -lboost_chrono -lboost_atomic -lpthread -lboost_filesystem -lboost_iostreams -lboost_regex -lboost_system -lboost_thread -lboost_chrono -lboost_atomic -lpthread -lconfig


lucenerrpp: cleanstate $(LUCENEOFILES) $(R2P2OFILES) linux-server.o
	g++  $(CXXFLAGS) -o $@ $(LUCENEOFILES) $(R2P2OFILES) linux-server.o $(LLUCE)

cleanstate:
	make -C ../../r2p2 clean

clean:
	rm -rf *.o $(TARGETS)
	rm -f lucene/*.o

.PHONY: clean
