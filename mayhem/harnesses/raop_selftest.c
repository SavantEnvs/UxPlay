/*
 * Known-answer functional test of UxPlay's request handling (upstream ships no test suite).
 * Starts the server exactly as the harnesses do (HLS support on), sends fixed requests over
 * loopback and checks the responses' status lines, headers and bodies.
 * Prints "PASS <name>" / "FAIL <name>" per case; mayhem/test.sh counts them.
 */
#include "raop_client.h"

static int passed, failed;

static void check(const char *name, int ok, const char *resp) {
    if (ok) {
        printf("PASS %s\n", name);
        passed++;
    } else {
        printf("FAIL %s\n--- response ---\n%s\n----------------\n", name, resp ? resp : "(null)");
        failed++;
    }
}

static long xchg(const char *req, char *resp, size_t cap) {
    return uxfuzz_exchange((const uint8_t *) req, strlen(req), resp, cap);
}

/* binary responses: search with memmem over the returned length */
static int has(const char *resp, long n, const char *needle) {
    return n > 0 && memmem(resp, (size_t) n, needle, strlen(needle)) != NULL;
}

int main(void) {
    static char r[65536];
    long n;

    if (uxfuzz_start_server(1) != 0) {
        printf("FAIL server_start\n");
        return 1;
    }

    n = xchg("OPTIONS * RTSP/1.0\r\nCSeq: 7\r\n\r\n", r, sizeof(r));
    check("rtsp_options", has(r, n, "RTSP/1.0 200 OK\r\n") && has(r, n, "CSeq: 7\r\n") &&
          has(r, n, "Public: SETUP, RECORD, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER\r\n") &&
          has(r, n, "Audio-Jack-Status: connected; type=digital\r\n"), r);

    {
        static const char two[] = "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n" UXFUZZ_SEP "OPTIONS * RTSP/1.0\r\nCSeq: 2\r\n\r\n";
        n = uxfuzz_exchange((const uint8_t *) two, sizeof(two) - 1, r, sizeof(r));
    }
    check("rtsp_pipelined", has(r, n, "CSeq: 1\r\n") && has(r, n, "CSeq: 2\r\n"), r);

    n = xchg("ANNOUNCE * RTSP/1.0\r\nCSeq: 3\r\n\r\n", r, sizeof(r));
    check("rtsp_not_implemented", has(r, n, "RTSP/1.0 501 Not Implemented\r\n") && has(r, n, "CSeq: 3\r\n"), r);

    n = xchg("OPTIONS * RTSP/1.0\r\nCSeq: -5\r\n\r\n", r, sizeof(r));
    check("rtsp_negative_cseq_dropped", n == 0, r);

    /* Not checked: a request with more than 20 header fields. conn_request (lib/raop.c) answers it
     * with a 431 response it never http_response_finish()es, so httpd's http_response_get_data()
     * asserts `response->complete` and the server aborts -- an upstream bug, left to the fuzzers. */

    n = xchg("GET /info RTSP/1.0\r\nCSeq: 5\r\n\r\n", r, sizeof(r));
    check("rtsp_get_info", has(r, n, "RTSP/1.0 200 OK\r\n") && has(r, n, "bplist00") &&
          has(r, n, "UxPlayFuzz") && has(r, n, "02:11:22:33:44:55"), r);

    n = xchg("GET /server-info HTTP/1.1\r\nX-Apple-Session-ID: 00000000-1111-2222-3333-444444444444\r\n\r\n",
             r, sizeof(r));
    check("http_server_info", has(r, n, "HTTP/1.1 200 OK\r\n") && has(r, n, "macAddress") &&
          has(r, n, "02:11:22:33:44:55"), r);

    n = xchg("garbage that is not http at all\r\n\r\n", r, sizeof(r));
    check("parse_error_closes", n == 0, r);

    printf("selftest: %d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
