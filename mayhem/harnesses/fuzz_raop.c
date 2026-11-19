/*
 * libFuzzer harness: UxPlay's AirPlay/RAOP server, fed over its real TCP listener.
 *
 * Built twice:
 *   fuzz_raop_rtsp     (default)     RTSP/RAOP control connection: CSeq'd requests reach
 *                                    raop_handlers.h (OPTIONS, GET /info, pair-setup/verify,
 *                                    pair-pin, fp-setup, SETUP bplists, GET/SET_PARAMETER, RECORD,
 *                                    FLUSH, TEARDOWN, feedback, audioMode).
 *   fuzz_airplay_http  (-DFUZZ_HLS)  same server with HLS support on (uxplay -hls), so requests
 *                                    without CSeq reach http_handlers.h (/reverse, /play, /action,
 *                                    /scrub, /rate, /getProperty, /setProperty, /playback-info,
 *                                    /server-info, /fp-setup2) and HLS GETs of *.m3u8 playlists
 *                                    (airplay_video.c).
 *
 * Each input is the byte stream one client sends on one TCP connection (any number of pipelined
 * requests). The harness sends it, half-closes, and waits until the server has answered and closed
 * the connection, so every byte has been parsed and handled before the next input starts.
 *
 * State kept across inputs on purpose: the one server instance (its pairing key, the hls flags).
 * The airplay_video playlist table (raop->airplay_video[], current_video) is per-session state: it
 * is cleared after every input with the library's public raop_destroy_airplay_video(raop, -1), so
 * an input's /action, /scrub, /getProperty or *.m3u8 GET never sees a playlist an earlier input
 * created and every crash reproduces from its own test case. A fresh connection gets a fresh
 * raop_conn_t (pairing session, fairplay, stream state); NOHOLD drops the previous RAOP connection when a new one identifies
 * itself, as on a real receiver. Restarting the server per input would cost a thread start, two
 * listening sockets and an ed25519 keygen per exec.
 */
#include "raop_client.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void) argc;
    (void) argv;
#ifdef FUZZ_HLS
    int hls = 1;
#else
    int hls = 0;
#endif
    if (uxfuzz_start_server(hls) != 0) {
        abort();
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_raop) {
        LLVMFuzzerInitialize(NULL, NULL);
    }
    (void) uxfuzz_exchange(data, size, NULL, 0);
    /* The server has closed the connection, so no handler is running: drop this input's playlists. */
    raop_destroy_airplay_video(g_raop, -1);
    return 0;
}
