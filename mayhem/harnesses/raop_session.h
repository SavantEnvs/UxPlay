/*
 * Client side of an AirPlay session for the stream harnesses (fuzz_mirror, fuzz_audio): the RTSP
 * SETUP exchange on the control connection and the client's NTP timing port.
 */
#ifndef UXPLAY_FUZZ_RAOP_SESSION_H
#define UXPLAY_FUZZ_RAOP_SESSION_H
#include "raop_client.h"
#include <plist/plist.h>

static int send_all(int fd, const char *p, size_t n) {
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return -1;
        }
        p += w;
        n -= (size_t) w;
    }
    return 0;
}

/* Read one RTSP response (headers + Content-Length body). Returns body length, -1 on EOF/error. */
static long read_response(int fd, char *buf, size_t cap, char **body) {
    size_t got = 0;
    char *hend = NULL;
    long clen = 0;
    for (;;) {
        if (!hend) {
            hend = memmem(buf, got, "\r\n\r\n", 4);
            if (hend) {
                *hend = '\0';
                char *cl = strcasestr(buf, "Content-Length:");
                clen = cl ? strtol(cl + 15, NULL, 10) : 0;
                hend += 4;
            }
        }
        if (hend && (size_t) (hend - buf) + (size_t) clen <= got) {
            *body = hend;
            return clen;
        }
        if (got >= cap) return -1;
        ssize_t n = recv(fd, buf + got, cap - got, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        got += (size_t) n;
    }
}

static long setup(int fd, int cseq, plist_t dict, char *resp, size_t cap, char **body) {
    char *bin = NULL;
    uint32_t binlen = 0;
    plist_to_bin(dict, &bin, &binlen);
    plist_free(dict);
    char hdr[512];
    int hl = snprintf(hdr, sizeof(hdr),
                      "SETUP rtsp://127.0.0.1/1 RTSP/1.0\r\nCSeq: %d\r\n"
                      "Content-Type: application/x-apple-binary-plist\r\n"
                      "User-Agent: AirPlay/690.7.1\r\nContent-Length: %u\r\n\r\n", cseq, binlen);
    int r = send_all(fd, hdr, (size_t) hl);
    if (!r) r = send_all(fd, bin, binlen);
    free(bin);
    if (r) return -1;
    return read_response(fd, resp, cap, body);
}

/* The client's NTP timing port. raop_ntp's thread queries it right after SETUP #1 and then waits
 * 300 ms for an answer; a stop request that arrives during that wait is missed and costs a full
 * 3 s sleep, so the harness answers the first query (as a real client does). */
static int g_ntp_fd = -1;
static unsigned short g_ntp_port;

static int ntp_open(void) {
    g_ntp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_ntp_fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(g_ntp_fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) return -1;
    socklen_t l = sizeof(sa);
    getsockname(g_ntp_fd, (struct sockaddr *) &sa, &l);
    g_ntp_port = ntohs(sa.sin_port);
    return 0;
}

static void ntp_drain(void) {
    unsigned char b[64];
    while (recv(g_ntp_fd, b, sizeof(b), MSG_DONTWAIT) > 0) {}
}

static void ntp_answer_one(void) {
    unsigned char req[64];
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    ssize_t n;
    do {
        n = recvfrom(g_ntp_fd, req, sizeof(req), 0, (struct sockaddr *) &from, &fl);
    } while (n < 0 && errno == EINTR);
    if (n < 32) return;
    unsigned char resp[32];
    memset(resp, 0, sizeof(resp));
    resp[0] = 0x80;
    resp[1] = 0xd3;
    resp[3] = 0x07;
    memcpy(resp + 8, req + 24, 8);   /* origin = their transmit time */
    memcpy(resp + 16, req + 24, 8);  /* receive  */
    memcpy(resp + 24, req + 24, 8);  /* transmit */
    sendto(g_ntp_fd, resp, sizeof(resp), 0, (struct sockaddr *) &from, fl);
}

/* SETUP #1: session keys + timing port (starts raop_ntp, inits raop_rtp/raop_rtp_mirror).
 * The ekey is not a real FairPlay-wrapped key: stream payloads decrypt to noise, while framing,
 * headers and unencrypted payload types are parsed as usual. Returns 0 on success. */
static int session_setup1(int ctl) {
    static char resp[65536];
    char *body = NULL;
    unsigned char ekey[72], eiv[16];
    for (int i = 0; i < 72; i++) ekey[i] = (unsigned char) (i * 7 + 1);
    for (int i = 0; i < 16; i++) eiv[i] = (unsigned char) (i * 13 + 5);

    plist_t s1 = plist_new_dict();
    plist_dict_set_item(s1, "ekey", plist_new_data((const char *) ekey, sizeof(ekey)));
    plist_dict_set_item(s1, "eiv", plist_new_data((const char *) eiv, sizeof(eiv)));
    plist_dict_set_item(s1, "timingProtocol", plist_new_string("NTP"));
    plist_dict_set_item(s1, "timingPort", plist_new_uint(g_ntp_port));
    plist_dict_set_item(s1, "deviceID", plist_new_string("AA:BB:CC:DD:EE:FF"));
    plist_dict_set_item(s1, "model", plist_new_string("iPhone14,2"));
    plist_dict_set_item(s1, "name", plist_new_string("fuzz"));
    plist_dict_set_item(s1, "isScreenMirroringSession", plist_new_bool(1));
    ntp_drain();
    if (setup(ctl, 1, s1, resp, sizeof(resp), &body) < 0) return -1;
    ntp_answer_one();

    return 0;
}

/* SETUP #2 with one stream dict; returns the reply plist (caller frees) or NULL */
static plist_t session_setup_stream(int ctl, plist_t stream) {
    static char resp[65536];
    char *body = NULL;
    plist_t s2 = plist_new_dict();
    plist_t streams = plist_new_array();
    plist_array_append_item(streams, stream);
    plist_dict_set_item(s2, "streams", streams);
    long blen = setup(ctl, 2, s2, resp, sizeof(resp), &body);
    if (blen <= 0) return NULL;
    plist_t root = NULL;
    plist_from_bin(body, (uint32_t) blen, &root);
    return root;
}

static uint64_t reply_stream_uint(plist_t root, const char *key) {
    uint64_t v = 0;
    plist_t rs = root ? plist_dict_get_item(root, "streams") : NULL;
    plist_t r0 = rs ? plist_array_get_item(rs, 0) : NULL;
    plist_t n = r0 ? plist_dict_get_item(r0, key) : NULL;
    if (n) plist_get_uint_val(n, &v);
    return v;
}

/* Close the control connection and wait until the server has closed it: httpd's conn_destroy
 * stops and joins the session's NTP, audio and mirror threads before closing the socket. */
static void session_teardown(int ctl) {
    shutdown(ctl, SHUT_WR);
    char buf[4096];
    for (;;) {
        ssize_t n = recv(ctl, buf, sizeof(buf), 0);
        if (n > 0) continue;
        if (n < 0 && errno == EINTR) continue;
        break;
    }
    close(ctl);
}

#endif
