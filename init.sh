#!/bin/sh

# Allocate huge pages
sudo sh -c 'for i in /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages; do echo 4096 > $i; done'
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

# Manage modules
sudo modprobe uio
sudo insmod dpdk/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko

# Remove the device
sudo ifdown $DEVICE_NAME
sudo ./dpdk/usertools/dpdk-devbind.py --bind=igb_uio $PCI_ADDR

# get dependencies
sudo apt-get install -y libconfig-dev libnuma-dev
