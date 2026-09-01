/*
 * proto.h - a2tp wire format, shared by every client/server port
 * (Linux client & server, Windows client).  Kept in its own header so a
 * port can include it without dragging in POSIX headers.
 *
 *   UDP payload:
 *     u8 type    A2TP_TYPE_DATA      -> payload is one Ethernet frame
 *               A2TP_TYPE_KEEPALIVE  -> payload empty, refresh peer only
 *
 *   --tcp mode carries the same payloads over a stream, framed as
 *   u16 be N, then N bytes (u8 type + payload, N >= 1).
 *
 *   Challenge auth (tcp only, server started with --pubkey): right after
 *   the connection is established the server sends AUTH_CHALLENGE with a
 *   fresh 96-bit challenge -- u64 be unix-ms timestamp + u32 be random
 *   nonce -- and the client must answer AUTH_RESPONSE with a 64-byte
 *   ssh-ed25519 signature over those 12 bytes.  Replaying a recorded
 *   response needs the server to reissue the exact same challenge: the
 *   u64 ms timestamp makes that impossible across time (the clock has
 *   moved on), leaving a same-millisecond 2^-32 nonce collision.  The
 *   server also rejects responses whose challenge timestamp has drifted
 *   out of a small freshness window.
 */
#ifndef A2TP_PROTO_H
#define A2TP_PROTO_H

#define A2TP_UDP_PORT      1702
#define A2TP_TYPE_DATA      0x01
#define A2TP_TYPE_KEEPALIVE 0x02
#define A2TP_TYPE_AUTH_CHALLENGE 0x03   /* payload: u64 ts + u32 nonce (12 B) */
#define A2TP_TYPE_AUTH_RESPONSE  0x04   /* payload: 64-byte ed25519 signature */

#define MAX_FRAME   65536   /* max inner Ethernet frame (+ headroom for type byte) */
#define HDR_LEN     1       /* sizeof(type field) */

#endif /* A2TP_PROTO_H */
