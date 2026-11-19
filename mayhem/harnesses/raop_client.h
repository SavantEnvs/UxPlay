/*
 * Shared server setup + loopback client for the UxPlay fuzz harnesses and the selftest.
 *
 * The only public way into UxPlay's request handling is its TCP listener: raop_start_httpd()
 * spawns the httpd thread (lib/httpd.c), which feeds received bytes to llhttp
 * (http_request_add_data) and dispatches complete requests to raop.c conn_request ->
 * raop_handlers.h (RTSP/RAOP) or http_handlers.h (AirPlay video / HLS). This file brings the
 * server up once, exactly the way uxplay.cpp (start_dnssd + start_raop_server) does, and
 * provides a client that delivers one byte buffer over one loopback connection.
 */
#ifndef UXPLAY_FUZZ_RAOP_CLIENT_H
#define UXPLAY_FUZZ_RAOP_CLIENT_H

#define _GNU_SOURCE 1
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <linux/sockios.h>

#include "raop.h"
#include "dnssd.h"
#include "logger.h"

static raop_t *g_raop;
static dnssd_t *g_dnssd;
static unsigned short g_port;

/* No-op renderer callbacks: the GStreamer frontend is not part of the parsed surface. */
static void cb_audio_process(void *cls, raop_ntp_t *ntp, audio_decode_struct *data) { (void) cls; (void) ntp; (void) data; }
static void cb_video_process(void *cls, raop_ntp_t *ntp, video_decode_struct *data) { (void) cls; (void) ntp; (void) data; }
static void cb_void(void *cls) { (void) cls; }
static void cb_conn_reset(void *cls, int reason) { (void) cls; (void) reason; }
static void cb_video_reset(void *cls, reset_type_t t) { (void) cls; (void) t; }
static void cb_teardown(void *cls, bool *a, bool *b) { (void) cls; (void) a; (void) b; }
static double cb_get_volume(void *cls) { (void) cls; return 0.0; }
static void cb_set_volume(void *cls, float v) { (void) cls; (void) v; }
static void cb_buf(void *cls, const void *b, int l) { (void) cls; (void) b; (void) l; }
static void cb_remote(void *cls, const char *a, const char *b) { (void) cls; (void) a; (void) b; }
static void cb_progress(void *cls, uint32_t *a, uint32_t *b, uint32_t *c) { (void) cls; (void) a; (void) b; (void) c; }
static void cb_report_size(void *cls, float *a, float *b, float *c, float *d) { (void) cls; (void) a; (void) b; (void) c; (void) d; }
static void cb_pin(void *cls, char *pin) { (void) cls; (void) pin; }
static void cb_register(void *cls, const char *a, const char *b, const char *c) { (void) cls; (void) a; (void) b; (void) c; }
static int cb_set_codec(void *cls, video_codec_t c) { (void) cls; (void) c; return 0; }
static void cb_play(void *cls, const char *loc, const float pos) { (void) cls; (void) loc; (void) pos; }
static void cb_float(void *cls, const float f) { (void) cls; (void) f; }
static void cb_pbinfo(void *cls, playback_info_t *p) { (void) cls; (void) p; }
static float cb_playlist_remove(void *cls) { (void) cls; return 0.0f; }

static int uxfuzz_start_server(int hls) {
    /* A peer closing its end while the server writes a response must not kill the process
     * (uxplay itself runs inside GStreamer/glib, which ignores SIGPIPE). */
    signal(SIGPIPE, SIG_IGN);

    raop_callbacks_t cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.audio_process = cb_audio_process;
    cbs.video_process = cb_video_process;
    cbs.video_pause = cb_void;
    cbs.video_resume = cb_void;
    cbs.conn_feedback = cb_void;
    cbs.conn_reset = cb_conn_reset;
    cbs.video_reset = cb_video_reset;
    cbs.conn_init = cb_void;
    cbs.conn_destroy = cb_void;
    cbs.conn_teardown = cb_teardown;
    cbs.audio_flush = cb_void;
    cbs.video_flush = cb_void;
    cbs.audio_set_client_volume = cb_get_volume;
    cbs.audio_set_volume = cb_set_volume;
    cbs.audio_set_metadata = cb_buf;
    cbs.audio_set_coverart = cb_buf;
    cbs.audio_stop_coverart_rendering = cb_void;
    cbs.audio_remote_control_id = cb_remote;
    cbs.audio_set_progress = cb_progress;
    cbs.video_report_size = cb_report_size;
    cbs.display_pin = cb_pin;
    cbs.register_client = cb_register;
    cbs.export_dacp = cb_remote;
    cbs.video_set_codec = cb_set_codec;
    cbs.on_video_play = cb_play;
    cbs.on_video_scrub = cb_float;
    cbs.on_video_rate = cb_float;
    cbs.on_video_stop = cb_void;
    cbs.on_video_acquire_playback_info = cb_pbinfo;
    cbs.on_video_playlist_remove = cb_playlist_remove;

    const char hw_addr[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    int err = 0;
    g_dnssd = dnssd_init("UxPlayFuzz", 10, hw_addr, 6, &err, 0);
    if (!g_dnssd || err) {
        fprintf(stderr, "dnssd_init failed: %d\n", err);
        return -1;
    }
    g_raop = raop_init(&cbs);
    if (!g_raop) {
        fprintf(stderr, "raop_init failed\n");
        return -1;
    }
    raop_set_log_level(g_raop, LOGGER_EMERG);
    /* "" keyfile: a fresh ed25519 key, never written to disk */
    if (raop_init2(g_raop, 1, "02:11:22:33:44:55", "")) {
        fprintf(stderr, "raop_init2 failed\n");
        return -1;
    }
    if (hls) {
        raop_set_plist(g_raop, "hls", 1);
    }
    g_port = 0;
    if (raop_start_httpd(g_raop, &g_port) < 0 || g_port == 0) {
        fprintf(stderr, "raop_start_httpd failed\n");
        return -1;
    }
    raop_set_port(g_raop, g_port);
    raop_set_dnssd(g_raop, g_dnssd);
    /* Builds the TXT records that GET /info returns; the mDNS registration itself fails
     * (no avahi daemon in the image), which uxplay also tolerates. */
    (void) dnssd_register_raop(g_dnssd, g_port);
    (void) dnssd_register_airplay(g_dnssd, g_port);
    return 0;
}

/* Requests inside one input are separated by this marker. UxPlay's httpd hands each recv() chunk
 * to one http_request_t and drops the connection when a chunk holds more than one request (a real
 * client waits for each response), so the harness delivers segment by segment. */
#define UXFUZZ_SEP "\x00\xffNEXT\xff\x00"
#define UXFUZZ_SEP_LEN 8

/* The server-side fd of our connection: the one whose peer is our local address. -1 if the server
 * has not accepted it yet or has already closed it. */
static int uxfuzz_server_fd(const struct sockaddr_in *me, unsigned short port) {
    for (int fd = 3; fd < 4096; fd++) {
        struct sockaddr_in peer, local;
        socklen_t pl = sizeof(peer), ll = sizeof(local);
        if (getpeername(fd, (struct sockaddr *) &peer, &pl) != 0 || pl != sizeof(peer) ||
            peer.sin_family != AF_INET) continue;
        if (peer.sin_port != me->sin_port || peer.sin_addr.s_addr != me->sin_addr.s_addr) continue;
        if (getsockname(fd, (struct sockaddr *) &local, &ll) != 0 || local.sin_port != htons(port)) continue;
        return fd;
    }
    return -1;
}

static int uxfuzz_server_fd_is(int sfd, const struct sockaddr_in *me) {
    struct sockaddr_in peer;
    socklen_t pl = sizeof(peer);
    return getpeername(sfd, (struct sockaddr *) &peer, &pl) == 0 && pl == sizeof(peer) &&
           peer.sin_port == me->sin_port && peer.sin_addr.s_addr == me->sin_addr.s_addr;
}

struct uxfuzz_sink { char *out; size_t cap; long got; int closed; };

/* Drain whatever the server has sent so far (non-blocking). Sets closed on EOF/error. */
static void uxfuzz_drain(int fd, struct uxfuzz_sink *k) {
    char buf[4096];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) {
            if (k->out && k->cap && (size_t) k->got < k->cap - 1) {
                size_t c = (size_t) n;
                if ((size_t) k->got + c > k->cap - 1) c = k->cap - 1 - (size_t) k->got;
                memcpy(k->out + k->got, buf, c);
            }
            k->got += n;
            continue;
        }
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) k->closed = 1;
        return;
    }
}

/* Send one segment, then wait until the server thread has read all of it out of its socket
 * (our unacked send queue is empty and the server socket's receive queue is empty). The server
 * handles a chunk right after reading it, so the next segment starts a new recv(). */
static void uxfuzz_send_segment(int fd, unsigned short port, int *sfd, const struct sockaddr_in *me,
                                const uint8_t *p, size_t n, struct uxfuzz_sink *k) {
    size_t sent = 0;
    while (!k->closed) {
        if (sent < n) {
            ssize_t w = send(fd, p + sent, n - sent, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (w > 0) sent += (size_t) w;
            else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { k->closed = 1; break; }
        }
        uxfuzz_drain(fd, k);
        if (sent >= n) {
            int outq = 0, inq = 0;
            if (ioctl(fd, SIOCOUTQ, &outq) != 0) break;
            if (outq == 0) {
                if (*sfd < 0 || !uxfuzz_server_fd_is(*sfd, me)) *sfd = uxfuzz_server_fd(me, port);
                if (*sfd >= 0 && ioctl(*sfd, FIONREAD, &inq) == 0 && inq == 0) break;
                if (*sfd < 0) {
                    /* not accepted yet, or already closed by the server: closed shows up in drain */
                }
            }
        }
        sched_yield();
    }
}

/* Deliver one input over one fresh loopback connection: each UXFUZZ_SEP-separated segment is sent
 * on its own (see above), then the client half-closes and collects everything the server answers
 * until the server closes the connection (it does once it reads EOF). Returns the number of
 * response bytes (stored NUL-terminated into out, truncated to outcap-1), or -1. */
/* connect to 127.0.0.1:port; fills *me with our local address */
static int uxfuzz_connect(unsigned short port, struct sockaddr_in *me) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    socklen_t ml = sizeof(*me);
    getsockname(fd, (struct sockaddr *) me, &ml);
    return fd;
}

static long uxfuzz_exchange(const uint8_t *data, size_t size, char *out, size_t outcap) {
    struct sockaddr_in me;
    int fd = uxfuzz_connect(g_port, &me);
    if (fd < 0) {
        return -1;
    }

    struct uxfuzz_sink k = { out, outcap, 0, 0 };
    int sfd = -1;
    size_t pos = 0;
    while (pos < size && !k.closed) {
        const uint8_t *sep = memmem(data + pos, size - pos, UXFUZZ_SEP, UXFUZZ_SEP_LEN);
        size_t end = sep ? (size_t) (sep - data) : size;
        if (end > pos) {
            uxfuzz_send_segment(fd, g_port, &sfd, &me, data + pos, end - pos, &k);
        }
        pos = sep ? end + UXFUZZ_SEP_LEN : size;
    }
    shutdown(fd, SHUT_WR);
    while (!k.closed) {
        struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&p, 1, -1) < 0 && errno != EINTR) break;
        uxfuzz_drain(fd, &k);
    }
    close(fd);
    if (out && outcap) {
        out[(size_t) k.got < outcap ? (size_t) k.got : outcap - 1] = '\0';
    }
    return k.got;
}

#endif
