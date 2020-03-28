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

.PHONY: dpdk dpdk-apps linux-apps

all:
	make dpdk-apps
	make linux-apps

dpdk:
	make -C dpdk config T=x86_64-native-linuxapp-gcc
	make -C dpdk -sj
	bash -c "mv dpdk/build dpdk/x86_64-native-linuxapp-gcc"

dpdk-apps:
	make -C dpdk-apps

linux-apps:
	make -C linux-apps

clean:
	make -C r2p2 clean
	make -C dpdk-apps cleanstate
	make -C linux-apps/ clean

style:
	find r2p2 -name "*.c" | xargs clang-format -i -style=file
	find r2p2 -name "*.h" | xargs clang-format -i -style=file
	find netstack -name "*.c" | xargs clang-format -i -style=file
	find netstack -name "*.h" | xargs clang-format -i -style=file
	find linux-apps -name "*.c" | xargs clang-format -i -style=file

.PHONY: linux-apps dpdk-apps
