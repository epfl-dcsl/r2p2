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

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <r2p2/cfg.h>
#include <r2p2/mempool.h>
#include <r2p2/r2p2-linux.h>
#include <r2p2/utils.h>
#ifdef WITH_TIMESTAMPING
#include <r2p2/timestamping.h>
#endif

struct r2p2_socket sock;
struct sockaddr_in router_addr;

static __thread int efd;
static __thread struct socket_pool sp;
static __thread struct fixed_mempool *buf_pool;

#ifdef WITH_TIMESTAMPING
/*
 * Update tx_timestamp in r2p2_ctx if it's smaller than the current one.
 */
static void update_tx_timestamp(void *event_arg)
{
	struct timespec tx_timestamp;
	struct r2p2_socket *s;
	int ret;

	s = container_of(event_arg, struct r2p2_socket, fd);
	ret = extract_tx_timestamp(s->fd, &tx_timestamp);
	if (ret != -1 && s->taken) {
		if (s->cp->ctx->tx_timestamp.tv_nsec == 0) {
			s->cp->ctx->tx_timestamp.tv_sec = tx_timestamp.tv_sec;
			s->cp->ctx->tx_timestamp.tv_nsec = tx_timestamp.tv_nsec;
		} else if (tx_timestamp.tv_sec != 0 &&
				   is_smaller_than(&tx_timestamp, &s->cp->ctx->tx_timestamp)) {
			s->cp->ctx->tx_timestamp.tv_sec = tx_timestamp.tv_sec;
			s->cp->ctx->tx_timestamp.tv_nsec = tx_timestamp.tv_nsec;
		}
	}
}
#endif

int r2p2_init_per_core(int core_id, int core_count)
{
	int ret, i, s, ephemeral_port, tfd;
	struct epoll_event event;
	struct sockaddr_in si_me;
	struct r2p2_socket *r2p2s;
#ifdef WITH_TIMESTAMPING
	int err;
#endif

	if (r2p2_backend_init_per_core()) {
		printf("Error init r2p2lib backend\n");
		return -1;
	}

	assert(((unsigned long)sp.sockets & 0x1F) == 0);
	// Create buffer pool
	buf_pool = create_mempool(BUFPOOL_SIZE, BUFLEN);
	assert(buf_pool);

	// Create epoll group
	efd = epoll_create(1);
	if (efd < 0) {
		printf("Error creating epoll fd\n");
		return -1;
	}

	// Add the server socket
	event.events = EPOLLIN;
	event.data.ptr = (void *)&sock.fd;
	ret = epoll_ctl(efd, EPOLL_CTL_ADD, sock.fd, &event);
	if (ret)
		return -1;

	// Create the client sockets
	for (i = 0; i < SOCKPOOL_SIZE; i++) {

		// create socket
		s = socket(AF_INET, SOCK_DGRAM, 0);
		assert(s);

		// make the socket nonblocking
		ret = fcntl(s, F_SETFL, O_NONBLOCK);
		if (ret == -1) {
			perror("nonblock: ");
			return ret;
		}
#ifdef WITH_TIMESTAMPING
		err = enable_hardware_timestamping(CFG.if_name);
		if (err) {
			perror("enabling hardware timestamping failed\n");
			return -1;
		}
		if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, CFG.if_name,
					   strlen(CFG.if_name))) {
			perror("setsockopt SO_BINDTODEVICE\n");
			return -1;
		}
		err = socket_enable_timestamping(s);
		if (err) {
			perror("sock enable timestamping failed\n");
			return -1;
		}
#endif
		// bind socket to port
		ephemeral_port = 33000 + i * core_count + core_id;
		si_me.sin_family = AF_INET;
		si_me.sin_port = htons(ephemeral_port);
		si_me.sin_addr.s_addr = htonl(INADDR_ANY);

		if (bind(s, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
			perror("Error binding port\n");
			return -1;
		}

		// Create timerfd
		tfd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);

		r2p2s = &sp.sockets[i];

		r2p2s->fd = s;
		r2p2s->tfd = tfd;
		r2p2s->local_host.port = ephemeral_port;
		r2p2s->local_host.ip = 0; // FIXME: set the ip too
		r2p2s->taken = 0;

		// add socket to epoll group
		event.events = EPOLLIN;
		event.data.ptr = (void *)&r2p2s->fd;
		ret = epoll_ctl(efd, EPOLL_CTL_ADD, s, &event);
		if (ret) {
			perror("epoll_ctl");
			return -1;
		}
		// add timerfd to epoll group
		event.events = EPOLLIN;
		event.data.ptr = (void *)&r2p2s->tfd;
		ret = epoll_ctl(efd, EPOLL_CTL_ADD, tfd, &event);
		if (ret) {
			perror("epoll_ctl");
			return -1;
		}
	}

	return 0;
}

/*
 * Socket management
 */
static struct r2p2_socket *get_socket(void)
{
	struct r2p2_socket *res;
	uint32_t idx;

	if (sp.count >= SOCKPOOL_SIZE)
		return NULL;

	while (sp.sockets[sp.idx++ & (SOCKPOOL_SIZE - 1)].taken)
		;
	idx = (sp.idx - 1) & (SOCKPOOL_SIZE - 1);
	res = &sp.sockets[idx];
	sp.sockets[idx].taken = 1;
	sp.count++;

	return res;
}

static int __disarm_timer(int timerfd)
{
	struct itimerspec ts = {0};

	// Disable timer
	if (timerfd_settime(timerfd, 0, &ts, NULL) < 0)
		assert(0);

	return 0;
}

static void free_socket(struct r2p2_socket *s)
{
	s->taken = 0;
	s->cp = NULL;
	sp.count--;
}

static void linux_on_client_pair_free(void *data)
{
	struct r2p2_socket *sock = (struct r2p2_socket *)data;
	__disarm_timer(sock->tfd);
	free_socket(sock);
}

static void handle_timer_for_socket(struct r2p2_socket *s)
{
	// Disable timer
	__disarm_timer(s->tfd);
	if (s->taken)
		timer_triggered(s->cp);
}

/*
 * Generic buffer implementation
 */
generic_buffer get_buffer(void)
{
	generic_buffer res;
	struct linux_buf_hdr *bhdr;

	res = alloc_object(buf_pool);
	if (!res)
		printf("No buffer available...\n");
	assert(res);
	bhdr = (struct linux_buf_hdr *)res;
	bzero(bhdr, sizeof(struct linux_buf_hdr));

	return res;
}

void *get_buffer_payload(generic_buffer gb)
{
	struct linux_buf_hdr *bhdr = (struct linux_buf_hdr *)gb;
	return &bhdr->payload;
}

void free_buffer(generic_buffer gb)
{
	free_object(gb);
}

uint32_t get_buffer_payload_size(generic_buffer gb)
{
	struct linux_buf_hdr *bhdr = (struct linux_buf_hdr *)gb;
	return bhdr->payload_size;
}

int set_buffer_payload_size(generic_buffer gb, uint32_t payload_size)
{
	struct linux_buf_hdr *bhdr = (struct linux_buf_hdr *)gb;
	bhdr->payload_size = payload_size;

	return 0;
}

int chain_buffers(generic_buffer first, generic_buffer second)
{
	struct linux_buf_hdr *bhdr = (struct linux_buf_hdr *)first;
	bhdr->next = second;

	return 0;
}

generic_buffer get_buffer_next(generic_buffer gb)
{
	struct linux_buf_hdr *bhdr = (struct linux_buf_hdr *)gb;
	return bhdr->next;
}

/*
 * R2P2 main functions
 */

int r2p2_init(int listen_port)
{
	int ret;
	struct sockaddr_in si_me;

	// create a UDP socket
	if ((sock.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		return -1;

	// zero out the structure
	memset((char *)&si_me, 0, sizeof(si_me));

	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(listen_port);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	// bind socket to port
	if (bind(sock.fd, (struct sockaddr *)&si_me, sizeof(si_me)) == -1)
		return -1;

	// make the socket nonblocking
	ret = fcntl(sock.fd, F_SETFL, O_NONBLOCK);
	if (ret == -1)
		return -1;

#if defined(WITH_ROUTER) || defined(WITH_TIMESTAMPING)
	if (parse_config())
		return -1;
#endif

#ifdef WITH_ROUTER
	// Configure router addr
	router_addr.sin_family = AF_INET;
	router_addr.sin_port = htons(CFG.router_port);
	router_addr.sin_addr.s_addr = htobe32(CFG.router_addr);
#endif

	return 0;
}

void r2p2_poll(void)
{
	struct epoll_event events[MAX_EVENTS];
	int ready, i, recvlen, is_timer_event;
	struct r2p2_socket *s;
	generic_buffer gb;
	void *buf, *event_arg;
	struct r2p2_host_tuple source;
#ifdef WITH_TIMESTAMPING
	struct timespec rx_timestamp;
#else
	unsigned int slen = sizeof(struct sockaddr_in);
	struct sockaddr_in client;
#endif

	ready = epoll_wait(efd, events, MAX_EVENTS, 0);
	for (i = 0; i < ready; i++) {
		event_arg = (struct r2p2_socket *)events[i].data.ptr;
		assert(event_arg);
		if (events[i].events & EPOLLIN) {
			is_timer_event =
				(unsigned long)event_arg % sizeof(struct r2p2_socket);
			if (is_timer_event) {
				assert((unsigned long)event_arg % sizeof(struct r2p2_socket) ==
					   4);
				s = container_of(event_arg, struct r2p2_socket, tfd);
				handle_timer_for_socket(s);
			} else {
				// it's a receive event
				s = container_of(event_arg, struct r2p2_socket, fd);

				gb = get_buffer();
				assert(gb);
				buf = get_buffer_payload(gb);

#ifdef WITH_TIMESTAMPING
				recvlen = recv_timestamp(s->fd, &source, buf, &rx_timestamp);
#else
				recvlen = recvfrom(s->fd, buf, BUFLEN, 0,
								   (struct sockaddr *)&client, &slen);
				source.port = ntohs(client.sin_port);
				source.ip = ntohl(client.sin_addr.s_addr);
#endif
				if (recvlen < 0) {
					free_buffer(gb);
					return;
				}

#ifdef WITH_TIMESTAMPING
				handle_incoming_pck(gb, recvlen, &source, &s->local_host,
									&rx_timestamp);
#else
				handle_incoming_pck(gb, recvlen, &source, &s->local_host);
#endif
			}
		} else if (events[i].events & EPOLLERR) {
#ifdef WITH_TIMESTAMPING
			assert((unsigned long)event_arg % sizeof(struct r2p2_socket) == 0);
			update_tx_timestamp(event_arg);
#else
			assert(0);
#endif
		} else {
			printf("Other event type...\n");
			assert(0);
		}
	}
}

/*
 * Implementation specific internal functions
 */
int prepare_to_send(struct r2p2_client_pair *cp)
{
	struct r2p2_socket *s;
	struct itimerspec ts;

	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;
	ts.it_value.tv_sec = cp->ctx->timeout / 1000000;
	ts.it_value.tv_nsec = (cp->ctx->timeout % 1000000) * 1000;

	s = get_socket();
	if (!s) {
		cp->ctx->error_cb(cp->ctx->arg, -ERR_NO_SOCKET);
		return -1;
	}
	s->cp = cp;
	// Arm the timer
	if (timerfd_settime(s->tfd, 0, &ts, NULL) < 0) {
		perror("Error setting timer:");
		assert(0);
	}

	cp->timer = (void *)(long)s->tfd;
	cp->request.sender = s->local_host;
	// FIXME: Should set ip too
	cp->impl_data = (void *)s;
	cp->on_free = linux_on_client_pair_free;

	return 0;
}

int buf_list_send(generic_buffer first_buf, struct r2p2_host_tuple *dest,
				  void *socket_info)
{
	struct sockaddr_in server;
	socklen_t len = sizeof(server);
	int sock_fd, buflen, ret;
	struct r2p2_socket *s;
	generic_buffer *gb;
	char *buf;

	if (socket_info) {
		s = (struct r2p2_socket *)socket_info;
		sock_fd = s->fd;
	} else
		sock_fd = sock.fd;

	server.sin_family = AF_INET;
	server.sin_port = htons(dest->port);
	server.sin_addr.s_addr = htonl(dest->ip);

	gb = first_buf;
	while (gb != NULL) {
		buf = get_buffer_payload(gb);
		buflen = get_buffer_payload_size(gb);
		ret = sendto(sock_fd, buf, buflen, 0, (struct sockaddr *)&server, len);
		if (ret < 0) {
			perror("Error sending msg:");
			return ret;
		}
		gb = get_buffer_next(gb);
	}
	ret = 0;
	return ret;
}

int disarm_timer(void *timer)
{
	int tfd = (int)(long)timer;
	return __disarm_timer(tfd);
}

void router_notify(uint32_t ip, uint16_t port, uint16_t rid)
{
#ifdef WITH_ROUTER
	int ret;
	char buf[64];

	r2p2_prepare_feedback(buf, ip, port, rid);
	socklen_t len = sizeof(struct sockaddr_in);

	ret = sendto(sock.fd, buf,
			sizeof(struct r2p2_header) + sizeof(struct r2p2_feedback), 0,
			(struct sockaddr *)&router_addr, len);
	assert(ret == sizeof(struct r2p2_header) + sizeof(struct r2p2_feedback));
#endif
}
