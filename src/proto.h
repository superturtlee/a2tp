/*
 * proto.h - a2tp wire format, shared by the server and the client
 *
 *   UDP payload:
 *     u8 type    A2TP_TYPE_DATA      -> payload is one Ethernet frame
 *               A2TP_TYPE_KEEPALIVE  -> payload empty, refresh peer only
 */
#ifndef A2TP_PROTO_H
#define A2TP_PROTO_H

#define A2TP_UDP_PORT      1702
#define A2TP_TYPE_DATA      0x01
#define A2TP_TYPE_KEEPALIVE 0x02

#define MAX_FRAME   65536   /* max inner Ethernet frame (+ headroom for type byte) */
#define HDR_LEN     1       /* sizeof(type field) */

#endif /* A2TP_PROTO_H */
