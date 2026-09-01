/*
 * auth.c - ssh-format ed25519 key parsing + sign/verify via libcrypto.
 *
 * The two containers are walked by hand (they are just length-prefixed
 * strings); every cryptographic operation goes through OpenSSL EVP:
 *
 *   authorized_keys entry:  "ssh-ed25519 " base64( ssh-string "ssh-ed25519"
 *                            . ssh-string key[32] ) [comment]
 *   id_ed25519 (openssh-key-v1, cipher "none"):
 *     "openssh-key-v1\0" . string cipher . string kdf . string kdfopts
 *     . u32 nkeys . string pubkeyblob . string {
 *         u32 check1 . u32 check2 (equal)
 *         . string "ssh-ed25519" . string pub[32]
 *         . string priv[64] = seed[32] || pub[32] . string comment }
 */
#include "auth.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- ssh wire primitives: u32 be length + payload ---------- */

struct rd {
    const uint8_t *p;
    size_t left;
};

static int rd_u32(struct rd *r, uint32_t *out)
{
    if (r->left < 4)
        return -1;
    *out = ((uint32_t)r->p[0] << 24) | ((uint32_t)r->p[1] << 16) |
           ((uint32_t)r->p[2] << 8) | (uint32_t)r->p[3];
    r->p += 4;
    r->left -= 4;
    return 0;
}

static int rd_str(struct rd *r, const uint8_t **out, size_t *olen)
{
    uint32_t n;
    if (rd_u32(r, &n) < 0 || r->left < n)
        return -1;
    *out = r->p;
    *olen = n;
    r->p += n;
    r->left -= n;
    return 0;
}

static int rd_expect(struct rd *r, const char *s)
{
    const uint8_t *p;
    size_t n;
    if (rd_str(r, &p, &n) < 0 || n != strlen(s) || memcmp(p, s, n) != 0)
        return -1;
    return 0;
}

/* ---------- base64 (whitespace-tolerant) ---------- */

static int b64_val(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

/* decode only the base64 chars of src (skip \n, \r, spaces); stop at '='
 * or a non-alphabet char; -1 on bad padding alignment */
static long b64_decode(const char *src, size_t slen, uint8_t *out, size_t osz)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t n = 0;

    for (size_t i = 0; i < slen; i++) {
        int v = b64_val((unsigned char)src[i]);
        if (v < 0) {
            if (src[i] == '=' || src[i] == '\n' || src[i] == '\r' ||
                src[i] == ' ' || src[i] == '\t')
                continue;
            return -1;
        }
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= osz)
                return -1;
            out[n++] = (uint8_t)(acc >> bits);
        }
    }
    return (long)n;
}

/* ---------- crypto (libcrypto EVP) ---------- */

int a2tp_random(uint8_t *buf, size_t n)
{
    return RAND_bytes(buf, (int)n) == 1 ? 0 : -1;
}

int a2tp_challenge_build(uint8_t chal[A2TP_CHALLENGE_LEN], uint64_t now_ms)
{
    if (a2tp_random(chal + 8, 4) < 0)
        return -1;
    for (int i = 0; i < 8; i++)                     /* u64 be timestamp */
        chal[i] = (uint8_t)(now_ms >> (56 - 8 * i));
    return 0;
}

uint64_t a2tp_challenge_ts(const uint8_t chal[A2TP_CHALLENGE_LEN])
{
    uint64_t ms = 0;
    for (int i = 0; i < 8; i++)
        ms = (ms << 8) | chal[i];
    return ms;
}

int ssh_sign(const uint8_t seed[32], const uint8_t *msg, size_t mlen,
             uint8_t sig[A2TP_SIG_LEN])
{
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                               seed, 32);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    size_t sl = A2TP_SIG_LEN;
    int rc = -1;

    if (k && c && EVP_DigestSignInit(c, NULL, NULL, NULL, k) == 1 &&
        EVP_DigestSign(c, sig, &sl, msg, mlen) == 1 &&
        sl == A2TP_SIG_LEN)
        rc = 0;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(k);
    return rc;
}

int ssh_verify(const uint8_t pub[32], const uint8_t *msg, size_t mlen,
               const uint8_t sig[A2TP_SIG_LEN])
{
    EVP_PKEY *k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                              pub, 32);
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int rc = -1;

    if (k && c && EVP_DigestVerifyInit(c, NULL, NULL, NULL, k) == 1)
        rc = EVP_DigestVerify(c, sig, A2TP_SIG_LEN, msg, mlen) == 1 ? 1 : 0;
    EVP_MD_CTX_free(c);
    EVP_PKEY_free(k);
    return rc;
}

/* ---------- authorized_keys ---------- */

/* one decoded key blob -> raw key, 0 = ok */
static int pubblob_parse(const uint8_t *b, size_t n, uint8_t out[32])
{
    struct rd r = { b, n };
    const uint8_t *k;
    size_t kl;

    if (rd_expect(&r, "ssh-ed25519") < 0 || rd_str(&r, &k, &kl) < 0 ||
        kl != 32)
        return -1;
    memcpy(out, k, 32);
    return 0;
}

int ssh_pubkeys_load(const char *path, uint8_t out[][32], int max)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[8192];
    int n = 0;
    while (n < max && fgets(line, sizeof(line), f)) {
        /* each whitespace-separated token may be a key blob; the blob
         * itself carries the "ssh-ed25519" type string, so tokens are
         * self-describing -- try every plausible one */
        for (char *tok = strtok(line, " \t\r\n"); tok;
             tok = strtok(NULL, " \t\r\n")) {
            uint8_t blob[256];
            long bl = b64_decode(tok, strlen(tok), blob, sizeof(blob));
            if (bl < 35 || pubblob_parse(blob, (size_t)bl, out[n]) < 0)
                continue;
            n++;
            break;   /* one key per authorized_keys line */
        }
    }
    fclose(f);
    return n;
}

/* ---------- openssh-key-v1 private key ---------- */

int ssh_privkey_load(const char *path, uint8_t seed[32])
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    /* collect the base64 between the BEGIN/END markers */
    char b64[8192];
    size_t bl = 0;
    char line[512];
    int inside = 0, ended = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!inside) {
            if (strstr(line, "BEGIN OPENSSH PRIVATE KEY"))
                inside = 1;
            continue;
        }
        if (strstr(line, "END OPENSSH PRIVATE KEY")) {
            ended = 1;
            break;
        }
        size_t l = strlen(line);
        if (bl + l >= sizeof(b64))
            break;
        memcpy(b64 + bl, line, l);
        bl += l;
    }
    fclose(f);
    if (!ended)
        return -1;

    uint8_t buf[4096];
    long n = b64_decode(b64, bl, buf, sizeof(buf));
    if (n < 64)
        return -1;

    struct rd r = { buf, (size_t)n };
    const uint8_t *cipher, *kdf, *kdfopts, *pubblob, *priv, *pub, *seedstr;
    size_t cipher_l, kdf_l, kdfopts_l, pubblob_l, priv_l, pub_l, seed_l;
    uint32_t nkeys, check1, check2;

    if (r.left < 15 || memcmp(r.p, "openssh-key-v1", 14) != 0 || r.p[14])
        return -1;
    r.p += 15;
    r.left -= 15;

    if (rd_str(&r, &cipher, &cipher_l) < 0 || rd_str(&r, &kdf, &kdf_l) < 0 ||
        rd_str(&r, &kdfopts, &kdfopts_l) < 0 || rd_u32(&r, &nkeys) < 0 ||
        rd_str(&r, &pubblob, &pubblob_l) < 0 ||
        rd_str(&r, &priv, &priv_l) < 0 || nkeys != 1)
        return -1;
    if (!(cipher_l == 4 && memcmp(cipher, "none", 4) == 0))
        return -2;   /* passphrase-encrypted: not supported */

    struct rd pr = { priv, priv_l };
    if (rd_u32(&pr, &check1) < 0 || rd_u32(&pr, &check2) < 0 ||
        check1 != check2 || rd_expect(&pr, "ssh-ed25519") < 0 ||
        rd_str(&pr, &pub, &pub_l) < 0 || pub_l != 32 ||
        rd_str(&pr, &seedstr, &seed_l) < 0 || seed_l != 64)
        return -1;

    /* the private string is seed(32) || pub(32) */
    if (memcmp(seedstr + 32, pub, 32) != 0)
        return -1;
    memcpy(seed, seedstr, 32);
    return 0;
}
