/*
 * libFuzzer harness: UxPlay's audio RTP receiver (lib/raop_rtp.c + raop_buffer.c), fed over the
 * UDP data and control ports that a client's SETUP opens.
 *
 * Per input, as an AirPlay audio client does:
 *   1. RTSP control connection: SETUP #1 (keys, timing port) and SETUP #2 with
 *      streams = [{type 96, ct, spf, controlPort}] -> raop_rtp_start_audio; the reply carries the
 *      server's dataPort and controlPort.
 *   2. The rest of the input is a list of datagrams, each
 *        [1 byte: bit 0 = port (0 data, 1 control)] [2 bytes big-endian length] [payload]
 *      (a short last record takes what is left). Each is sendto()'d and the harness waits until
 *      the audio thread has read it (the server socket's receive queue is empty) before the next.
 *      Data port: RTP audio packets (raop_buffer enqueue/decrypt/dequeue). Control port: sync
 *      (0x54) and resent-audio (0x56) packets.
 *   3. Close the control connection; conn_destroy joins the audio thread before the server closes
 *      it, so the whole input has been handled when the harness returns.
 * The first input byte picks the codec the client announces (bit 0: ct=2 ALAC or ct=8 AAC-ELD),
 * which is client-controlled SETUP data and switches raop_rtp/raop_buffer code paths.
 */
#include "raop_session.h"

/* the server's UDP socket bound to `port` (dataPort / controlPort live in this process) */
static int udp_server_fd(unsigned short port) {
    for (int fd = 3; fd < 4096; fd++) {
        int type = 0;
        socklen_t tl = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tl) != 0 || type != SOCK_DGRAM) continue;
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        if (getsockname(fd, (struct sockaddr *) &ss, &sl) != 0) continue;
        unsigned short p = 0;
        if (ss.ss_family == AF_INET) p = ntohs(((struct sockaddr_in *) &ss)->sin_port);
        else if (ss.ss_family == AF_INET6) p = ntohs(((struct sockaddr_in6 *) &ss)->sin6_port);
        if (p == port) return fd;
    }
    return -1;
}

static int g_udp = -1;   /* client-side socket: sends to both ports, receives resend requests */

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    if (uxfuzz_start_server(0) != 0 || ntp_open() != 0) {
        abort();
    }
    g_udp = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (g_udp < 0 || bind(g_udp, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        abort();
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_raop) {
        LLVMFuzzerInitialize(NULL, NULL);
    }
    if (size < 1) {
        return -1;
    }
    struct sockaddr_in cme;
    int ctl = uxfuzz_connect(g_port, &cme);
    if (ctl < 0 || session_setup1(ctl) != 0) {
        abort();  /* our own server is not answering: setup is broken, not the input */
    }
    struct sockaddr_in me;
    socklen_t ml = sizeof(me);
    getsockname(g_udp, (struct sockaddr *) &me, &ml);

    int aac = data[0] & 1;
    plist_t st = plist_new_dict();
    plist_dict_set_item(st, "type", plist_new_uint(96));
    plist_dict_set_item(st, "ct", plist_new_uint(aac ? 8 : 2));
    plist_dict_set_item(st, "spf", plist_new_uint(aac ? 480 : 352));
    plist_dict_set_item(st, "audioFormat", plist_new_uint(aac ? 0x1000000 : 0x40000));
    plist_dict_set_item(st, "controlPort", plist_new_uint(ntohs(me.sin_port)));
    plist_dict_set_item(st, "isMedia", plist_new_bool(1));
    plist_t root = session_setup_stream(ctl, st);
    unsigned short ports[2];
    ports[0] = (unsigned short) reply_stream_uint(root, "dataPort");
    ports[1] = (unsigned short) reply_stream_uint(root, "controlPort");
    plist_free(root);
    if (!ports[0] || !ports[1]) {
        fprintf(stderr, "fuzz_audio: SETUP did not open audio ports\n");
        abort();
    }
    int sfd[2] = { udp_server_fd(ports[0]), udp_server_fd(ports[1]) };

    size_t pos = 1;
    while (pos < size) {
        int which = data[pos] & 1;
        size_t len = size - pos - 1;
        size_t hdr = 1;
        if (len >= 2) {
            size_t want = ((size_t) data[pos + 1] << 8) | data[pos + 2];
            hdr = 3;
            len = size - pos - 3;
            if (want < len) len = want;
        } else {
            hdr = 1 + len;
            len = 0;
        }
        const uint8_t *p = data + pos + hdr;
        pos += hdr + len;
        if (len == 0) {
            continue;  /* an empty datagram cannot be told apart from an empty queue below */
        }
        struct sockaddr_in to;
        memset(&to, 0, sizeof(to));
        to.sin_family = AF_INET;
        to.sin_port = htons(ports[which]);
        to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (sendto(g_udp, p, len, 0, (struct sockaddr *) &to, sizeof(to)) < 0) {
            continue;
        }
        /* wait until the audio thread has taken the datagram off its socket */
        for (;;) {
            int inq = 0;
            if (sfd[which] < 0 || ioctl(sfd[which], FIONREAD, &inq) != 0 || inq == 0) break;
            sched_yield();
        }
        unsigned char junk[2048];
        while (recv(g_udp, junk, sizeof(junk), MSG_DONTWAIT) > 0) {}  /* resend requests */
    }

    session_teardown(ctl);
    unsigned char junk[2048];
    while (recv(g_udp, junk, sizeof(junk), MSG_DONTWAIT) > 0) {}
    return 0;
}
