# R2P2 - Request Response Pair Protocol

R2P2 is a UDP-based transport protocol specifically targetting microsecond-scale RPCs.
R2P2 exposes pairs of requests and responses and allows efficient and scalable RPC routing by separating the RPC target selection from request and reply streaming.

The existing R2P2 implementation supports both a Linux-based implementation mostly for testing, and a DPDK-based implementation for performance.

## Building R2P2

To build and run R2P2 you need to build DPDK and prepare the machine to run an R2P2 application.
The ``init.sh`` fetches and builds DPDK, allocates hugepages, and configures the NIC for use with DPDK.
Specifically:

```bash
export DEVICE_NAME=<your-interface-name>
export PCI_ADDR=<the-devive-pci-address>
git submodule update --init --recursive
make dpdk
make
./init.sh
```

## Code Structure

The repository is structured as follows:

* ``r2p2``
	This folder holds the main R2P2 implementation used both for Linux on top of UDP sockets and on top of DPDK.

* ``netstack``
	This folder holds a mininal networking stack on top of DPDK implementing Ethernet, IP, UDP, ICMP, and ARP layers.

* ``linux-apps``
	This folder holds sample linux server and client applications as examples.

* ``dpdk-apps``
	This folder holds sample dpdk server applications and the software R2P2 router.

* ``r2p2.conf.sample``
	R2P2 expects to find a configuration file under ``/etc/r2p2.conf``. We provide a sample configuration file. **Important!** Make sure you provide a valid configuration file at the right location before running any examples.


## Run R2P2 examples

After building the code you can run the following echo examples.
The client sends 10 requests to the server and the server echoes back the received payload.

### Linux client - Linux server

On the server machine run:

```bash
./linux-apps/linux_server # this will run an R2P2 echo server on port 8000
```

On the client machine run:
```bash
./linux-apps/linux_client <server_ip> 8000
```

### Linux client - DPDK server

On the server machine run:

```bash
sudo ./dpdk-apps/r2p2-echo -l 0 # this will run a single-threaded R2P2 server
```

On the client machine run:
```bash
./linux-apps/linux_client <server_ip> 8000
```

### Linux client - Router - Server
In this example you are going to use the R2P2 router between the R2P2 client and the R2P2 server.

For a Linux server:
```bash
make -C linux-apps/ WITH_ROUTER=1
./linux-apps/linux_server
```

For a DPDK server:
```bash
sudo ./dpdk-apps/r2p2-echo-fdir -l 0
```

To run the router:
```bash
sudo ./dpdk-apps/r2p2-router -l 0,2 -- <server_ip>:8000:1 0 rr
```

On the client machine run:
```bash
./linux-apps/linux_client <router_ip> 8000
```

## R2P2 Router

The R2P2 router can run either as a software middlebox or as part of a Tofino ASIC. In this repository we only include the software DPDK implementation.


### Software Router options
```bash
Usage: ./router -l 0,2 -- <target_ip:base_port:count,...> <per_queue_slots> <rand|rr|fc>
```

The software router runs on 2 cores (0,2) and implements 3 different policies: ``rand`` for random selections, ``rr``for round-robin, and ``fc`` for JBSQ.
The takes a comaseparated list of servers. For each server provide the target ip, the base port, and how many ports this server exposes separated by colon. For example 10.0.0.1:8000:2 registers 2 queues to the R2P2 router both at 10.0.0.1, one at 8000, and one at 8001. The ``per_queue_slots`` arguement is only useful in the JBSQ(n) case and it's the ``n``. For the other policies, this argument should be 0.

### HovercRaft

To run R2P2 with the HovercRaft extension (See the Eurosys [paper](https://infoscience.epfl.ch/record/276586) for more details) you need to build with `WITH_RAFT=1` as described in the HovercRaft [repo](https://github.com/epfl-dcsl/hovercraft).

Also, you need to configure your `r2p2.conf` accirdingly. Specifically, you need to add raft peers and the used multicast groups as in the `r2p2.conf.sample`.


### HovercRaft++

For HovercRaft++ (in-network acceleration for HovercRaft) you need to also add the switch peer. So, in the `raft` section of your `r2p2.conf` you need to have an even number of peers, and the last one corresponds to the switch.

### P4 Source Code
For the P4 source code for `JBSQ` and `HovercRaft++` please contact <marios.kogias@epfl.ch>.
