/*
 * common.h - shared helpers for a2tp-srv / a2tp-cli
 *
 * A minimal L2TPv3-over-UDP style tunnel carrying raw Ethernet frames.
 * The wire format lives in proto.h (shared with the Windows port): a u8
 * message type -- data frame, keepalive, challenge, response -- with the
 * framing details chosen by the transport (udp datagrams / tcp u16 prefix).
 */
#ifndef A2TP_COMMON_H
#define A2TP_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "proto.h"   /* wire format constants shared with the Windows port */

/* global verbosity, set from -v in each program */
extern int g_verbose;

/* keep going flag set by SIGINT/SIGTERM */
extern volatile sig_atomic_t g_stop;

void die(const char *fmt, ...) __attribute__((noreturn, format(printf, 1, 2)));
void logmsg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void logv(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void hexdump(const uint8_t *p, size_t n, size_t max);

/* monotonic clock in milliseconds */
int64_t now_ms(void);

/* pack an IPv4 endpoint (ip + port, both network order) into one atomic-friendly
 * word so worker threads can publish/refresh the roamed peer without a lock */
uint64_t sockaddr_key(const struct sockaddr_in *a);
void     key_to_sockaddr(uint64_t key, struct sockaddr_in *a);

/* ---------- threading helpers ---------- */
/* notification pipe: worker threads wake main (blocking reader, async-safe
 * nonblocking writers); main blocks in read() instead of polling */
int  evpipe_create(int fds[2]);                 /* -1 = errno */
void evpipe_notify(int fd);                     /* write one byte */
void sock_rcvtimeo(int fd, int ms);             /* idle tick for blocked readers */
void block_termination_signals(void);           /* workers: only main takes signals */

/* parse "1.2.3.4:1702" (":1702" and "1.2.3.4" also accepted -> default port) */
int parse_ip_port(const char *s, uint16_t def_port, struct sockaddr_in *out);

/* parse "aa:bb:cc:dd:ee:ff" */
int parse_mac(const char *s, uint8_t out[6]);

/* UDP socket bound to INADDR_ANY:local_port (0 = ephemeral) */
int udp_bind(uint32_t bind_ip /* network order */, uint16_t local_port);

/* ---------- TCP transport (--tcp) ------------------------------------- *
 * The stream carries the same payloads as UDP, framed for the byte stream:
 *
 *   u16 be length N, then N bytes  (u8 type + payload, N >= 1)
 *
 * One connection at a time; a dropped connection is re-accepted (server) or
 * re-connected (client).  The point is kernel TCP congestion control and
 * retransmission (pick the algorithm via sysctl -- bbr is the kernel's job).
 */
int  tcp_listen_on(struct in_addr bind_addr, uint16_t port);   /* -1 = errno */
int  tcp_connect_to(const struct sockaddr_in *dst, int timeout_ms);
void tcp_tune(int fd);   /* NODELAY + buffers + send deadline (cc left to the kernel) */

int  stream_send_msg(int fd, const uint8_t *msg, size_t len);  /* 0 / -1 */

/* incremental framed-message reader (poll-driven) */
struct stream_rx {
    uint8_t *buf;   /* caller-provided, >= 2 + HDR_LEN + MAX_FRAME */
    size_t   have;  /* bytes buffered so far */
    size_t   need;  /* bytes wanted for the current part */
    int      hdr;   /* 1 = reading the 2-byte length, 0 = reading the message */
};
void stream_rx_init(struct stream_rx *rx, uint8_t *buf);
int  stream_rx_feed(struct stream_rx *rx, int fd);   /* 1 msg ready / 0 need more / -1 dead */
void stream_rx_next(struct stream_rx *rx);           /* start the next message */

/* True if the Ethernet frame carries IPv4/{UDP,TCP} involving the tunnel
 * itself: port pair {local_port, peer_port} (peer_port 0 = wildcard) and,
 * when peer_ip != 0, src or dst IP equals peer_ip. Used to avoid mirroring
 * the tunnel's own packets back into the tunnel. */
int frame_is_tunnel_l4(const uint8_t *frame, size_t len, int proto,
                       uint16_t local_port, uint32_t peer_ip, uint16_t peer_port);

/* VLAN-unwrapped ethertype of an Ethernet frame, 0 when it is too short */
uint16_t frame_ethertype(const uint8_t *frame, size_t len);

/* IPv4 destination of an Eth[+VLAN]+IPv4 frame, 0 when it is not IPv4
 * (0.0.0.0 is not a usable unicast dst, so 0 means "no match candidate") */
uint32_t frame_ipv4_dst(const uint8_t *frame, size_t len);

/* misc interface helpers via ioctl on an AF_INET control socket */
int  ctl_socket(void);
int  if_up(const char *ifname, int promisc);          /* IFF_UP[|IFF_PROMISC] */
int  if_set_mac(const char *ifname, const uint8_t mac[6]);
int  if_set_mtu(const char *ifname, int mtu);
int  if_get_mtu(const char *ifname, int *mtu);
int  if_get_mac(const char *ifname, uint8_t mac[6]);

#define OFFLOAD_N 3   /* tso, gso, gro */
int  if_offload_save(const char *ifname, int ov[OFFLOAD_N]);   /* -1 = unknown */
int  if_offload_apply(const char *ifname, const int ov[OFFLOAD_N]);
int  if_disable_offloads(const char *ifname);  /* tso/gso/gro off (mirror must
                                                  see real wire frames) */

void install_signal_handlers(void);

#endif /* A2TP_COMMON_H */
