/*
 * libFuzzer harness: UxPlay's screen-mirroring stream (lib/raop_rtp_mirror.c), fed over the TCP
 * data port that a client's SETUP opens.
 *
 * Per input, exactly what an AirPlay client does:
 *   1. RTSP control connection: SETUP #1 (bplist with ekey/eiv/timingPort -> fairplay_decrypt,
 *      raop_ntp/raop_rtp/raop_rtp_mirror init) and SETUP #2 (streams = [{type 110}] ->
 *      raop_rtp_mirror_start); the reply's streams[0].dataPort is the mirror port.
 *   2. Connect to dataPort and send the input as the mirror stream (128-byte packet headers +
 *      payloads: video, SPS/PPS codec data, heartbeats, type-5 plists), segment by segment
 *      (UXFUZZ_SEP), each read by the mirror thread before the next is sent; then half-close.
 *   3. Close the control connection. httpd's conn_destroy stops and joins the mirror and NTP
 *      threads before it closes the socket, so the EOF the harness waits for means the whole
 *      input has been processed.
 * The ekey is not a real FairPlay-wrapped key, so encrypted video payloads decrypt to noise;
 * packet framing, codec-data (SPS/PPS) parsing and plist payloads are reached all the same.
 */
#include "raop_session.h"

static unsigned short start_mirror(int ctl) {
    if (session_setup1(ctl) != 0) return 0;
    plist_t st = plist_new_dict();
    plist_dict_set_item(st, "type", plist_new_uint(110));
    plist_dict_set_item(st, "streamConnectionID", plist_new_uint(0x1122334455667788ULL));
    plist_t root = session_setup_stream(ctl, st);
    unsigned short port = (unsigned short) reply_stream_uint(root, "dataPort");
    plist_free(root);
    return port;
}
int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
    if (uxfuzz_start_server(0) != 0 || ntp_open() != 0) {
        abort();
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_raop) {
        LLVMFuzzerInitialize(NULL, NULL);
    }
    struct sockaddr_in cme;
    int ctl = uxfuzz_connect(g_port, &cme);
    if (ctl < 0) {
        abort();  /* our own server is not listening: setup is broken, not the input */
    }
    unsigned short dport = start_mirror(ctl);
    if (!dport) {
        fprintf(stderr, "fuzz_mirror: SETUP did not open a mirror data port\n");
        abort();
    }

    struct sockaddr_in me;
    int fd = uxfuzz_connect(dport, &me);
    if (fd >= 0) {
        struct uxfuzz_sink k = { NULL, 0, 0, 0 };
        int sfd = -1;
        size_t pos = 0;
        while (pos < size && !k.closed) {
            const uint8_t *sep = memmem(data + pos, size - pos, UXFUZZ_SEP, UXFUZZ_SEP_LEN);
            size_t end = sep ? (size_t) (sep - data) : size;
            if (end > pos) {
                uxfuzz_send_segment(fd, dport, &sfd, &me, data + pos, end - pos, &k);
            }
            pos = sep ? end + UXFUZZ_SEP_LEN : size;
        }
        shutdown(fd, SHUT_WR);
    }

    session_teardown(ctl);
    if (fd >= 0) close(fd);
    return 0;
}
