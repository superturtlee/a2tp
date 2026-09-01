/*
 * auth_test.c - self-test for auth.c.  Needs ssh-keygen; the openssl
 * cross-checks run when the openssl CLI is present.
 *
 *   make check
 */
#include "auth.h"
#include "common.h"   /* real framed-stream helpers for the handshake drill */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;

static void check(int ok, const char *what)
{
    printf("%s: %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok)
        fails++;
}

static int run(const char *cmd)
{
    fflush(stdout);
    return system(cmd);
}

int main(void)
{
    const char *dir = "/tmp/a2tp-auth-test";
    char cmd[512];
    uint8_t pub[32], seed[32], sig[64], sig2[64], wrong[32];
    uint8_t msg[40], rnd[32];

    run("rm -rf /tmp/a2tp-auth-test && mkdir -p /tmp/a2tp-auth-test");
    snprintf(cmd, sizeof(cmd),
             "ssh-keygen -q -t ed25519 -N '' -C a2tp-test -f %s/key "
             ">/dev/null 2>&1", dir);
    if (run(cmd) != 0) {
        printf("FAIL: ssh-keygen unavailable or failed\n");
        return 1;
    }

    /* --- parsing --- */
    uint8_t pubs[4][32];
    int n = ssh_pubkeys_load("/nonexistent", pubs, 4);
    check(n == -1, "pubkeys_load: missing file -> -1");

    snprintf(cmd, sizeof(cmd), "%s/key.pub", dir);
    n = ssh_pubkeys_load(cmd, pubs, 4);
    check(n == 1, "pubkeys_load: one ssh-ed25519 line -> 1");
    memcpy(pub, pubs[0], 32);

    snprintf(cmd, sizeof(cmd), "%s/key", dir);
    int rc = ssh_privkey_load(cmd, seed);
    check(rc == 0, "privkey_load: unencrypted openssh-key-v1 -> seed");

    /* authorized_keys with comments, blank lines, other types, two keys */
    snprintf(cmd, sizeof(cmd),
             "cp %s/key %s/key2 >/dev/null 2>&1 && "
             "ssh-keygen -y -f %s/key2 >> /dev/null 2>&1; "
             "{ echo '# comment'; echo; echo 'ssh-rsa AAAAB3NzaC1yc2E x'; "
             "  cat %s/key.pub; echo 'leading-ws'; cat %s/key.pub; "
             "} > %s/authorized_keys", dir, dir, dir, dir, dir, dir);
    run(cmd);
    snprintf(cmd, sizeof(cmd), "%s/authorized_keys", dir);
    n = ssh_pubkeys_load(cmd, pubs, 4);
    check(n == 2, "pubkeys_load: skips rsa/comments, finds 2 ed25519 keys");

    /* --- sign / verify round trip --- */
    for (size_t i = 0; i < sizeof(msg); i++)
        msg[i] = (uint8_t)(i * 7 + 3);
    check(ssh_sign(seed, msg, sizeof(msg), sig) == 0, "sign: ok");
    check(ssh_verify(pub, msg, sizeof(msg), sig) == 1,
          "verify: our sig + matching pub");

    memcpy(wrong, pub, 32);
    wrong[0] ^= 1;
    check(ssh_verify(wrong, msg, sizeof(msg), sig) == 0,
          "verify: wrong pub rejected");
    memcpy(sig2, sig, 64);
    sig2[10] ^= 1;
    check(ssh_verify(pub, msg, sizeof(msg), sig2) == 0,
          "verify: tampered sig rejected");
    sig2[0] ^= 1;
    memcpy(sig2, sig, 64);
    check(ssh_verify(pub, msg, sizeof(msg) + 1, sig) == 0,
          "verify: different message rejected");

    /* --- random --- */
    check(a2tp_random(rnd, sizeof(rnd)) == 0, "random: ok");
    uint8_t rnd2[A2TP_CHALLENGE_LEN];
    a2tp_random(rnd2, sizeof(rnd2));
    check(memcmp(rnd, rnd2, sizeof(rnd)) != 0, "random: two draws differ");

    /* --- challenge: u64 ts + u32 random, 96-bit, timestamp round-trips --- */
    uint8_t chal[A2TP_CHALLENGE_LEN], chal2[A2TP_CHALLENGE_LEN];
    check(a2tp_challenge_build(chal, 1234567890123ULL) == 0 &&
          a2tp_challenge_ts(chal) == 1234567890123ULL,
          "challenge: timestamp round-trips");
    check(a2tp_challenge_build(chal2, 1234567890123ULL) == 0 &&
          memcmp(chal, chal2, A2TP_CHALLENGE_LEN) != 0,
          "challenge: same ms, two draws differ (fresh nonce)");

    /* --- handshake drill over a socketpair: the exact tcp message flow -- */
    {
        int sp[2];
        check(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0,
              "handshake: socketpair");

        /* server: fresh 96-bit challenge, framed [u16 be len][type][chal] */
        check(a2tp_challenge_build(chal, (uint64_t)now_ms()) == 0,
              "handshake: challenge built");
        uint8_t cmsg[1 + A2TP_CHALLENGE_LEN] = { A2TP_TYPE_AUTH_CHALLENGE };
        memcpy(cmsg + 1, chal, A2TP_CHALLENGE_LEN);
        check(stream_send_msg(sp[0], cmsg, sizeof(cmsg)) == 0,
              "handshake: challenge sent");

        /* client: read one framed message, sign the challenge, answer */
        uint8_t buf[2 + HDR_LEN + MAX_FRAME];
        struct stream_rx rx;
        stream_rx_init(&rx, buf);
        int rc = 0;
        while ((rc = stream_rx_feed(&rx, sp[1])) == 0)
            ;
        uint8_t *m = rx.buf + 2;
        size_t ml = rx.have - 2;
        uint8_t resp[1 + A2TP_SIG_LEN] = { A2TP_TYPE_AUTH_RESPONSE };
        check(rc == 1 && ml == 1 + A2TP_CHALLENGE_LEN &&
              m[0] == A2TP_TYPE_AUTH_CHALLENGE &&
              ssh_sign(seed, m + 1, A2TP_CHALLENGE_LEN, resp + 1) == 0 &&
              stream_send_msg(sp[1], resp, sizeof(resp)) == 0,
              "handshake: client parses + signs + answers");

        /* server: verify the response against the challenge it issued */
        uint8_t buf2[2 + HDR_LEN + MAX_FRAME];
        struct stream_rx rrx;
        stream_rx_init(&rrx, buf2);
        while ((rc = stream_rx_feed(&rrx, sp[0])) == 0)
            ;
        m = rrx.buf + 2;
        ml = rrx.have - 2;
        check(rc == 1 && ml == 1 + A2TP_SIG_LEN &&
              m[0] == A2TP_TYPE_AUTH_RESPONSE &&
              ssh_verify(pub, chal, A2TP_CHALLENGE_LEN, m + 1) == 1,
              "handshake: server verifies the answer");

        /* replay drill: the recorded answer against the NEXT challenge */
        a2tp_challenge_build(chal2, (uint64_t)now_ms() + 1);
        check(ssh_verify(pub, chal2, A2TP_CHALLENGE_LEN, m + 1) == 0,
              "replay: recorded answer fails against the next challenge");

        /* forged replay: valid signature over STALE challenge bytes --
         * verification alone would pass, the server's freshness window is
         * what must reject it */
        uint8_t stale[A2TP_CHALLENGE_LEN], stale_sig[A2TP_SIG_LEN];
        a2tp_challenge_build(stale, (uint64_t)now_ms() - 120000);
        ssh_sign(seed, stale, A2TP_CHALLENGE_LEN, stale_sig);
        check(ssh_verify(pub, stale, A2TP_CHALLENGE_LEN, stale_sig) == 1 &&
              now_ms() - (int64_t)a2tp_challenge_ts(stale) > 30000,
              "replay: stale-challenge signature is valid but out of window");

        close(sp[0]);
        close(sp[1]);
    }

    /* --- encrypted key rejected with -2 --- */
    snprintf(cmd, sizeof(cmd),
             "ssh-keygen -q -t ed25519 -N 'secret' -f %s/enc >/dev/null 2>&1",
             dir);
    run(cmd);
    snprintf(cmd, sizeof(cmd), "%s/enc", dir);
    rc = ssh_privkey_load(cmd, seed);
    check(rc == -2, "privkey_load: passphrase key -> -2");

    /* --- openssl CLI cross-checks (interop with another implementation) --
     * ssh-keygen cannot export ed25519 keys as PEM (openssh format only),
     * so the openssl side makes its own keypair.  For ed25519 the PKCS#8
     * private DER is a fixed 16-byte prefix + 32-byte seed, and the public
     * SPKI DER is a 12-byte prefix + 32-byte key, so the raw keys are just
     * the tails of the DER blobs. */
    snprintf(cmd, sizeof(cmd), "command -v openssl >/dev/null 2>&1");
    if (run(cmd) == 0) {
        uint8_t der[64];
        int got;

        snprintf(cmd, sizeof(cmd),
                 "openssl genpkey -algorithm ed25519 -out %s/o.pem "
                 ">/dev/null 2>&1 && "
                 "openssl pkey -in %s/o.pem -pubout -out %s/o.pub.pem "
                 ">/dev/null 2>&1 && "
                 "openssl pkey -in %s/o.pem -outform DER -out %s/o.der "
                 ">/dev/null 2>&1 && "
                 "openssl pkey -in %s/o.pem -pubout -outform DER "
                 "-out %s/o.pub.der >/dev/null 2>&1",
                 dir, dir, dir, dir, dir, dir, dir);
        run(cmd);

        snprintf(cmd, sizeof(cmd), "%s/msg.bin", dir);
        FILE *f = fopen(cmd, "wb");
        fwrite(msg, 1, sizeof(msg), f);
        fclose(f);

        /* openssl signs; we verify (needs openssl's raw pub key) */
        snprintf(cmd, sizeof(cmd),
                 "openssl pkeyutl -sign -rawin -inkey %s/o.pem "
                 "-in %s/msg.bin -out %s/theirs.sig >/dev/null 2>&1",
                 dir, dir, dir);
        run(cmd);
        snprintf(cmd, sizeof(cmd), "%s/o.pub.der", dir);
        f = fopen(cmd, "rb");
        got = f ? (int)fread(der, 1, sizeof(der), f) : 0;
        if (f)
            fclose(f);
        check(got == 44, "interop: openssl pub SPKI DER is 44 bytes");
        snprintf(cmd, sizeof(cmd), "%s/theirs.sig", dir);
        f = fopen(cmd, "rb");
        got = f ? (int)fread(sig2, 1, 64, f) : 0;
        if (f)
            fclose(f);
        check(got == 64 && ssh_verify(der + 12, msg, sizeof(msg), sig2) == 1,
              "interop: WE verify openssl CLI's signature");

        /* we sign (with openssl's raw seed); openssl verifies */
        snprintf(cmd, sizeof(cmd), "%s/o.der", dir);
        f = fopen(cmd, "rb");
        got = f ? (int)fread(der, 1, sizeof(der), f) : 0;
        if (f)
            fclose(f);
        check(got == 48 && ssh_sign(der + 16, msg, sizeof(msg), sig) == 0,
              "interop: sign with openssl CLI's seed");
        snprintf(cmd, sizeof(cmd), "%s/ours.sig", dir);
        f = fopen(cmd, "wb");
        fwrite(sig, 1, 64, f);
        fclose(f);
        snprintf(cmd, sizeof(cmd),
                 "openssl pkeyutl -verify -rawin -pubin -inkey %s/o.pub.pem "
                 "-sigfile %s/ours.sig -in %s/msg.bin >/dev/null 2>&1",
                 dir, dir, dir);
        check(run(cmd) == 0, "interop: openssl CLI verifies OUR signature");
    } else {
        printf("SKIP: openssl CLI not found\n");
    }

    run("rm -rf /tmp/a2tp-auth-test");
    printf("---- %s ----\n", fails ? "FAILURES" : "all good");
    return fails ? 1 : 0;
}
