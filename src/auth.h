/*
 * auth.h - ssh-format ed25519 keys + challenge-response material.
 *
 * All cryptography is OpenSSL libcrypto (EVP ed25519, RAND_bytes); this
 * module only parses the OpenSSH key containers (authorized_keys lines,
 * the unencrypted openssh-key-v1 private-key envelope) down to the raw
 * 32-byte keys, and signs/verifies through EVP.
 *
 * Wire use (tcp only): the server sends A2TP_TYPE_AUTH_CHALLENGE carrying
 * a fresh 96-bit challenge -- u64 be unix-ms timestamp + u32 be random
 * nonce -- and the client answers A2TP_TYPE_AUTH_RESPONSE with a 64-byte
 * signature over those 12 bytes.  A recorded response only ever verifies
 * against its exact challenge, and the timestamp keeps the server from
 * reissuing one: replaying across time is impossible by clock monotonicity,
 * and within the same millisecond it takes a 2^-32 nonce collision.
 */
#ifndef A2TP_AUTH_H
#define A2TP_AUTH_H

#include <stddef.h>
#include <stdint.h>

#define A2TP_CHALLENGE_LEN 12   /* u64 be unix ms + u32 be random nonce */
#define A2TP_SIG_LEN       64

/* strong random bytes; 0 = ok, -1 = entropy failure */
int a2tp_random(uint8_t *buf, size_t n);

/* build a fresh challenge for unix-time `now_ms` (random low 32 bits);
 * 0 = ok, -1 = entropy failure */
int a2tp_challenge_build(uint8_t chal[A2TP_CHALLENGE_LEN], uint64_t now_ms);

/* the timestamp half of a challenge */
uint64_t a2tp_challenge_ts(const uint8_t chal[A2TP_CHALLENGE_LEN]);

/* sign msg with the seed -> 64-byte signature; 0 = ok, -1 = failure */
int ssh_sign(const uint8_t seed[32], const uint8_t *msg, size_t mlen,
             uint8_t sig[A2TP_SIG_LEN]);

/* 1 = valid, 0 = invalid, -1 = error */
int ssh_verify(const uint8_t pub[32], const uint8_t *msg, size_t mlen,
               const uint8_t sig[A2TP_SIG_LEN]);

/* every "ssh-ed25519 AAAA..." entry of an authorized_keys-style file
 * (other lines/key types ignored); returns the key count, -1 = file error */
int ssh_pubkeys_load(const char *path, uint8_t out[][32], int max);

/* unencrypted openssh-key-v1 private key (id_ed25519, no passphrase);
 * 0 = ok, -1 = bad format, -2 = passphrase-encrypted */
int ssh_privkey_load(const char *path, uint8_t seed[32]);

#endif /* A2TP_AUTH_H */
