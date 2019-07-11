/*
 * MIT License
 *
 * Copyright (c) 2019-2021 Ecole Polytechnique Federale Lausanne (EPFL)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <r2p2/timestamping.h>

#include <arpa/inet.h>
#include <assert.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <r2p2/r2p2-linux.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <unistd.h>

int is_smaller_than(const struct timespec *lhs, const struct timespec *rhs)
{
	if (lhs->tv_sec == rhs->tv_sec)
		return lhs->tv_nsec < rhs->tv_nsec;
	else
		return lhs->tv_sec < rhs->tv_sec;
}

static int set_timestamping_filter(int fd, char *if_name, int rx_filter,
								   int tx_type)
{
	struct ifreq ifr;
	struct hwtstamp_config config;

	config.flags = 0;
	config.tx_type = tx_type;
	config.rx_filter = rx_filter;

	strcpy(ifr.ifr_name, if_name);
	ifr.ifr_data = (caddr_t)&config;

	if (ioctl(fd, SIOCSHWTSTAMP, &ifr)) {
		perror("ERROR setting NIC timestamping: ioctl SIOCSHWTSTAMP");
		return -1;
	}
	return 0;
}

int enable_hardware_timestamping(char *if_name)
{
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int filter = HWTSTAMP_FILTER_ALL;
	int tx_type = HWTSTAMP_TX_ON;
	int ret;

	ret = set_timestamping_filter(fd, if_name, filter, tx_type);
	close(fd);
	return ret;
}

/*
 * Returns -1 if no new timestamp found
 * 1 if timestamp found
 */
static int extract_timestamps(struct msghdr *hdr, struct timespec *dest)
{
	struct cmsghdr *cmsg;
	struct scm_timestamping *ts;
	int found = -1;

	for (cmsg = CMSG_FIRSTHDR(hdr); cmsg != NULL;
		 cmsg = CMSG_NXTHDR(hdr, cmsg)) {
		if (cmsg->cmsg_type == SCM_TIMESTAMPING) {
			ts = (struct scm_timestamping *)CMSG_DATA(cmsg);
			if (ts->ts[2].tv_sec != 0) {
				// make sure we don't get multiple timestamps for the same
				assert(found == -1);
				dest->tv_sec = ts->ts[2].tv_sec;
				dest->tv_nsec = ts->ts[2].tv_nsec;
				found = 1;
			}
		}
	}
	return found;
}

int recv_timestamp(int sockfd, struct r2p2_host_tuple *source, void *buf,
				   struct timespec *last_rx_time)
{
	int nbytes;
	struct sockaddr_in client;
	unsigned int slen = sizeof(struct sockaddr_in);
	char recv_control[CONTROL_LEN] = {0};
	struct msghdr hdr = {0};
	struct iovec recv_iov;

	recv_iov.iov_base = buf;
	recv_iov.iov_len = BUFLEN;

	hdr.msg_iov = &recv_iov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = recv_control;
	hdr.msg_controllen = CONTROL_LEN;
	hdr.msg_name = (void *)&client;
	hdr.msg_namelen = slen;

	nbytes = recvmsg(sockfd, &hdr, 0);

	source->port = ntohs(client.sin_port);
	source->ip = client.sin_addr.s_addr;

	if (nbytes <= 0)
		return nbytes;
	bzero(last_rx_time, sizeof(struct timespec));
	extract_timestamps(&hdr, last_rx_time);

	return nbytes;
}

int socket_enable_timestamping(int fd)
{
	int ts_mode = 0;

	ts_mode |= SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_RAW_HARDWARE |
			   SOF_TIMESTAMPING_TX_HARDWARE;
	ts_mode |= SOF_TIMESTAMPING_OPT_TSONLY | SOF_TIMESTAMPING_OPT_ID;

	if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &ts_mode, sizeof(ts_mode)) <
		0) {
		perror(
			"ERROR enabling socket timestamping: setsockopt SO_TIMESTAMPING.");
		return -1;
	}
	return 0;
}

int extract_tx_timestamp(int sockfd, struct timespec *time)
{
	char tx_control[CONTROL_LEN] = {0};
	struct msghdr mhdr = {0};
	struct iovec junk_iov = {NULL, 0};
	ssize_t n;

	mhdr.msg_iov = &junk_iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = tx_control;
	mhdr.msg_controllen = CONTROL_LEN;

	n = recvmsg(sockfd, &mhdr, MSG_ERRQUEUE);
	if (n < 0) {
		return -1;
	}
	return extract_timestamps(&mhdr, time);
}
