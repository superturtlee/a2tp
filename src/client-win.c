/*
 * client-win.c - a2tp-cli for Windows: a TAP adapter cloned from the
 * server's NIC.  Native Win32 port of src/client.c (same wire format,
 * same threading model); needs the tap-windows6 driver (ComponentId
 * tap0901, shipped with OpenVPN) and an elevated console.
 *
 *   transport <-- server (promiscuous NIC) --> every frame into the TAP
 *   TAP --> every frame the host emits on the TAP goes to the server
 *           and is injected there onto the NIC
 *
 * Platform notes vs the Linux client:
 * - The adapter is a persistent device: it is enumerated from the registry
 *   and opened as \\.\Global\{GUID}.tap.  "Up" is a driver state: the
 *   TAP_IOCTL_SET_MEDIA_STATUS ioctl plugs the virtual cable in (and
 *   unplugs it on exit).  MAC and MTU live in the adapter's registry key
 *   and are only read at adapter start, so --mac/--mtu write the registry
 *   and bounce the adapter once via netsh before opening.
 * - IP configuration is left to netsh (like ip(8) on Linux); --ip/--mask/
 *   --gw are thin conveniences that shell out to netsh.
 * - Threads are winpthreads.  Teardown wakes blocking syscalls the
 *   Windows way: closesocket() breaks a blocked recv, CancelIoEx() breaks
 *   a blocked ReadFile on the TAP.  main waits on a manual-reset event
 *   instead of the event pipe.
 * - Lock-free where the Linux client is: UDP sends are one syscall each
 *   (datagram-atomic); the roamed server endpoint is one atomic u64.
 *   TCP has two writers (pump + keepalive) and Windows makes no atomicity
 *   promise for stream sends, so those take a small mutex and emit
 *   length header + payload with a single WSASend.
 * - The TAP is a synchronous handle (no overlapped I/O): ReadFile blocks
 *   until a frame arrives, WriteFile completes a whole frame.
 *
 * Cross-compile:  make a2tp-cli.exe   (x86_64-w64-mingw32-gcc, -static)
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>   /* winpthreads: same shape as the Linux client */

#include "proto.h"

#pragma pack(push, 1)

/* ---------- tap-windows6 ---------- */

#define TAP_COMPONENT_ID  "tap0901"

/* where the driver instances live; subkeys are "0000", "0001", ... */
#define NIC_CLASS_KEY \
    "SYSTEM\\CurrentControlSet\\Control\\Class" \
    "\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
/* friendly (netsh) name of an instance */
#define NIC_CONN_KEY_FMT \
    "SYSTEM\\CurrentControlSet\\Control\\Network" \
    "\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection"

#define TAP_MAX_ADAPTERS 16

struct tap_adapter {
    char guid[64];      /* NetCfgInstanceId, braces included */
    char name[128];     /* connection name, what netsh displays */
    char subkey[280];   /* full registry path of the instance key */
    char path[96];      /* \\.\Global\{...}.tap */
};

/* tap-windows6 ioctl numbers (see the driver's tap-windows.h) */
#define TAP_IOCTL_CONTROL_CODE(request, method) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_GET_VERSION      TAP_IOCTL_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU          TAP_IOCTL_CONTROL_CODE(3, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_IOCTL_CONTROL_CODE(5, METHOD_BUFFERED)

#pragma pack(pop)

/* ---------- logging (same output shape as common.c) ---------- */

static int g_verbose;
static volatile LONG g_stop;

static void die(const char *fmt, ...)
{
    va_list ap;
    fputs("fatal: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void logmsg(const char *fmt, ...)
{
    va_list ap;
    char ts[32];
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(ts, sizeof(ts), "%02d:%02d:%02d",
             st.wHour, st.wMinute, st.wSecond);
    fprintf(stderr, "[%s] ", ts);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void logv(const char *fmt, ...)
{
    va_list ap;
    if (!g_verbose)
        return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void hexdump(const uint8_t *p, size_t n, size_t max)
{
    size_t i, limit = n < max ? n : max;
    fprintf(stderr, "        %lu bytes:", (unsigned long)n);
    for (i = 0; i < limit; i++)
        fprintf(stderr, " %02x", p[i]);
    if (n > limit)
        fprintf(stderr, " ...");
    fputc('\n', stderr);
}

/* windows error text (winsock + GetLastError share the formatter) */
static const char *werr(DWORD e)
{
    static char buf[256];
    if (!e)
        return "success";
    if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL, e,
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       buf, sizeof(buf), NULL)) {
        size_t n = strlen(buf);
        while (n && (buf[n - 1] == '\r' || buf[n - 1] == '\n' || buf[n - 1] == ' '))
            buf[--n] = '\0';
        return buf;
    }
    snprintf(buf, sizeof(buf), "error %lu", (unsigned long)e);
    return buf;
}

static int64_t now_ms(void)
{
    return (int64_t)GetTickCount64();
}

/* ---------- config ---------- */

struct cfg {
    struct sockaddr_in srv;
    int have_srv;
    uint16_t local_port;
    int tcp;                    /* --tcp: framed stream transport */
    const char *tap;            /* adapter name or GUID (NULL = first) */
    uint8_t mac[6];
    int have_mac;
    int mtu;
    int keepalive_ms;
    const char *ip, *mask, *gw; /* optional: netsh static address */
    int list_only;              /* --list: print adapters and exit */
};

/* parse "1.2.3.4", "1.2.3.4:1702" or ":1702" into a sockaddr_in */
static int parse_ip_port(const char *s, uint16_t def_port, struct sockaddr_in *out)
{
    char buf[256], *colon;
    long port = def_port;

    if (!s || !*s)
        return -1;
    snprintf(buf, sizeof(buf), "%s", s);
    colon = strrchr(buf, ':');
    if (colon) {
        char *end = NULL;
        *colon = '\0';
        port = strtol(colon + 1, &end, 10);
        if (!end || *end || port < 0 || port > 65535 || !*buf)
            return -1;
    }
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((uint16_t)port);
    return inet_pton(AF_INET, buf, &out->sin_addr) == 1 ? 0 : -1;
}

static int parse_mac(const char *s, uint8_t out[6])
{
    unsigned int m[6];
    if (!s || sscanf(s, "%x:%x:%x:%x:%x:%x",
                     &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) {
        if (m[i] > 0xff)
            return -1;
        out[i] = (uint8_t)m[i];
    }
    return 0;
}

/* ---------- netsh shell-out (adapter bounce / static IP) ---------- */

/* run `netsh.exe <args>`, wait, 0 = exit code 0 */
static int sh_netsh(const char *args)
{
    char cmdline[1024];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD code = 1;

    snprintf(cmdline, sizeof(cmdline), "netsh.exe %s", args);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        logmsg("CreateProcess netsh failed: %s", werr(GetLastError()));
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (code != 0)
        logmsg("netsh %s: exit %lu", args, (unsigned long)code);
    return code == 0 ? 0 : -1;
}

/* ---------- registry helpers ---------- */

static int reg_read_str(HKEY root, const char *subkey, const char *value,
                        char *out, size_t outsz)
{
    HKEY k;
    DWORD type = 0, len = (DWORD)outsz;
    int rc = -1;

    if (RegOpenKeyExA(root, subkey, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
        return -1;
    out[0] = '\0';
    if (RegQueryValueExA(k, value, NULL, &type, (LPBYTE)out, &len) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ) && out[0])
        rc = 0;
    RegCloseKey(k);
    return rc;
}

static int reg_write_str(HKEY root, const char *subkey, const char *value,
                         const char *data)
{
    HKEY k;
    int rc = -1;

    if (RegOpenKeyExA(root, subkey, 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS)
        return -1;
    if (RegSetValueExA(k, value, 0, REG_SZ, (const BYTE *)data,
                       (DWORD)strlen(data) + 1) == ERROR_SUCCESS)
        rc = 0;
    RegCloseKey(k);
    return rc;
}

static int reg_read_dword(HKEY root, const char *subkey, const char *value,
                          DWORD *out)
{
    HKEY k;
    DWORD type = 0, len = sizeof(DWORD);
    int rc = -1;

    if (RegOpenKeyExA(root, subkey, 0, KEY_QUERY_VALUE, &k) != ERROR_SUCCESS)
        return -1;
    if (RegQueryValueExA(k, value, NULL, &type, (LPBYTE)out, &len) == ERROR_SUCCESS &&
        type == REG_DWORD)
        rc = 0;
    RegCloseKey(k);
    return rc;
}

static int reg_write_dword(HKEY root, const char *subkey, const char *value,
                           DWORD data)
{
    HKEY k;
    int rc = -1;

    if (RegOpenKeyExA(root, subkey, 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS)
        return -1;
    if (RegSetValueExA(k, value, 0, REG_DWORD, (const BYTE *)&data,
                       sizeof(data)) == ERROR_SUCCESS)
        rc = 0;
    RegCloseKey(k);
    return rc;
}

/* ---------- TAP adapter enumeration (registry) ---------- */

/*
 * Enumerate NIC instances, keep those with ComponentId tap0901, and fill
 * guid / connection name / device path.  Returns the number found.
 */
static int tap_enumerate(struct tap_adapter *out, int max)
{
    HKEY cls;
    int n = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, NIC_CLASS_KEY, 0, KEY_READ,
                      &cls) != ERROR_SUCCESS)
        return 0;

    for (DWORD i = 0; n < max; i++) {
        char sub[16], key[280], comp[64], guid[64], conn[300], name[128];
        DWORD len = sizeof(sub);
        LONG r = RegEnumKeyExA(cls, i, sub, &len, NULL, NULL, NULL, NULL);

        if (r == ERROR_NO_MORE_ITEMS)
            break;
        if (r != ERROR_SUCCESS)
            continue;
        snprintf(key, sizeof(key), "%s\\%s", NIC_CLASS_KEY, sub);
        if (reg_read_str(HKEY_LOCAL_MACHINE, key, "ComponentId",
                         comp, sizeof(comp)) < 0)
            continue;
        if (_stricmp(comp, TAP_COMPONENT_ID) != 0)
            continue;
        if (reg_read_str(HKEY_LOCAL_MACHINE, key, "NetCfgInstanceId",
                         guid, sizeof(guid)) < 0)
            continue;
        snprintf(conn, sizeof(conn), NIC_CONN_KEY_FMT, guid);
        if (reg_read_str(HKEY_LOCAL_MACHINE, conn, "Name",
                         name, sizeof(name)) < 0)
            snprintf(name, sizeof(name), "(unnamed)");

        struct tap_adapter *a = &out[n++];
        snprintf(a->guid, sizeof(a->guid), "%s", guid);
        snprintf(a->name, sizeof(a->name), "%s", name);
        snprintf(a->subkey, sizeof(a->subkey), "%s", key);
        snprintf(a->path, sizeof(a->path), "\\\\.\\Global\\%s.tap", guid);
    }
    RegCloseKey(cls);
    return n;
}

/* pick the adapter named by --tap (connection name or GUID, either case),
 * or the first one when no name was given */
static int tap_pick(const struct cfg *c, struct tap_adapter *out, int *count)
{
    struct tap_adapter list[TAP_MAX_ADAPTERS];
    int n = tap_enumerate(list, TAP_MAX_ADAPTERS);

    *count = n;
    if (n == 0)
        return -1;
    if (!c->tap) {
        *out = list[0];
        return 0;
    }
    for (int i = 0; i < n; i++)
        if (_stricmp(list[i].name, c->tap) == 0 ||
            _stricmp(list[i].guid, c->tap) == 0) {
            *out = list[i];
            return 0;
        }
    return -1;
}

static void tap_list_print(void)
{
    struct tap_adapter list[TAP_MAX_ADAPTERS];
    int n = tap_enumerate(list, TAP_MAX_ADAPTERS);

    if (n == 0) {
        fprintf(stderr, "no TAP adapters (ComponentId %s) found; install the "
                        "tap-windows6 driver (bundled with OpenVPN)\n",
                TAP_COMPONENT_ID);
        return;
    }
    fprintf(stderr, "%d TAP adapter(s):\n", n);
    for (int i = 0; i < n; i++)
        fprintf(stderr, "  [%d] name \"%s\"  guid %s\n", i,
                list[i].name, list[i].guid);
}

/* ---------- MAC / MTU (registry values read at adapter start) ---------- */

/* current MAC of the adapter as the stack sees it (by GUID match) */
static int tap_get_mac(const char *guid, uint8_t mac[6])
{
    ULONG bufsz = 128 * 1024;
    PIP_ADAPTER_ADDRESSES aa, p;
    int rc = -1;

    aa = malloc(bufsz);
    if (!aa)
        return -1;
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, aa, &bufsz) == ERROR_BUFFER_OVERFLOW) {
        free(aa);
        aa = malloc(bufsz);
        if (!aa || GetAdaptersAddresses(AF_UNSPEC, 0, NULL, aa, &bufsz)
                   != ERROR_SUCCESS) {
            free(aa);
            return -1;
        }
    }
    for (p = aa; p; p = p->Next) {
        if (p->PhysicalAddressLength == 6 && p->AdapterName &&
            _stricmp(p->AdapterName, guid) == 0) {
            memcpy(mac, p->PhysicalAddress, 6);
            rc = 0;
            break;
        }
    }
    free(aa);
    return rc;
}

/*
 * The tap-windows6 driver only looks at NetworkAddress / MTU when the
 * adapter starts, so apply-pending changes and bounce it via netsh once.
 * Skipped entirely when the registry already matches (the clone-MAC flow
 * sets --mac on every run but only the first one pays the restart).
 */
static int tap_apply_mac_mtu(const struct cfg *c, const struct tap_adapter *a)
{
    char want[16];
    DWORD cur_dword;
    char cur_str[32];
    int dirty = 0;

    if (!c->have_mac && c->mtu <= 0)
        return 0;

    if (c->have_mac) {
        uint8_t cur[6];
        snprintf(want, sizeof(want), "%02X%02X%02X%02X%02X%02X",
                 c->mac[0], c->mac[1], c->mac[2],
                 c->mac[3], c->mac[4], c->mac[5]);
        if (reg_read_str(HKEY_LOCAL_MACHINE, a->subkey, "NetworkAddress",
                         cur_str, sizeof(cur_str)) < 0 ||
            _stricmp(cur_str, want) != 0) {
            if (tap_get_mac(a->guid, cur) == 0 && memcmp(cur, c->mac, 6) == 0) {
                /* registry empty but the running MAC already matches:
                 * nothing to do */
            } else if (reg_write_str(HKEY_LOCAL_MACHINE, a->subkey,
                                     "NetworkAddress", want) < 0) {
                logmsg("writing NetworkAddress failed (need Administrator?)");
                return -1;
            } else {
                dirty = 1;
            }
        }
    }
    if (c->mtu > 0) {
        if (reg_read_dword(HKEY_LOCAL_MACHINE, a->subkey, "MTU", &cur_dword) < 0 ||
            cur_dword != (DWORD)c->mtu) {
            if (reg_write_dword(HKEY_LOCAL_MACHINE, a->subkey, "MTU",
                                (DWORD)c->mtu) < 0) {
                logmsg("writing MTU failed (need Administrator?)");
                return -1;
            }
            dirty = 1;
        }
    }
    if (!dirty)
        return 0;

    char args[300];
    logmsg("adapter config changed, bouncing \"%s\" for it to take effect",
           a->name);
    snprintf(args, sizeof(args), "interface set interface name=\"%s\" disable", a->name);
    if (sh_netsh(args) < 0)
        return -1;
    snprintf(args, sizeof(args), "interface set interface name=\"%s\" enable", a->name);
    if (sh_netsh(args) < 0)
        return -1;

    /* the device needs a moment before it can be opened again */
    for (int i = 0; i < 50; i++) {
        uint8_t mac[6];
        int ok = 1;
        if (c->have_mac && (tap_get_mac(a->guid, mac) < 0 ||
                            memcmp(mac, c->mac, 6) != 0))
            ok = 0;
        if (ok)
            return 0;
        Sleep(100);
    }
    if (c->have_mac) {
        uint8_t mac[6] = {0};
        tap_get_mac(a->guid, mac);
        logmsg("warning: adapter MAC is %02x:%02x:%02x:%02x:%02x:%02x, "
               "wanted %02x:%02x:%02x:%02x:%02x:%02x",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
               c->mac[0], c->mac[1], c->mac[2], c->mac[3], c->mac[4], c->mac[5]);
    }
    return 0;
}

/* ---------- TAP device I/O ---------- */

static HANDLE tap_open_dev(const char *path)
{
    /* right after a netsh enable the device may not exist yet: retry */
    for (int i = 0; i < 50; i++) {
        HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE)
            return h;
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED)
            die("open %s: %s\n"
                "the TAP device needs an elevated console "
                "(run as Administrator)", path, werr(e));
        if (i == 49)
            die("open %s: %s", path, werr(e));
        Sleep(100);
    }
    return INVALID_HANDLE_VALUE;   /* not reached */
}

static int tap_ioctl(HANDLE h, DWORD code, void *in, DWORD inlen,
                     void *out, DWORD outlen)
{
    DWORD br = 0;
    if (!DeviceIoControl(h, code, in, inlen, out, outlen, &br, NULL))
        return -1;
    return 0;
}

static void tap_media_status(HANDLE h, int up)
{
    ULONG v = up ? TRUE : FALSE;
    if (tap_ioctl(h, TAP_IOCTL_SET_MEDIA_STATUS, &v, sizeof(v),
                  &v, sizeof(v)) < 0)
        logmsg("TAP_IOCTL_SET_MEDIA_STATUS(%d) failed: %s",
               up, werr(GetLastError()));
}

static int tap_write_frame(HANDLE h, const uint8_t *f, size_t n)
{
    DWORD w = 0;
    if (!WriteFile(h, f, (DWORD)n, &w, NULL) || w != (DWORD)n)
        return -1;
    return 0;
}

/* one frame per ReadFile; <0 = error, 0 = aborted (teardown) */
static int tap_read_frame(HANDLE h, uint8_t *buf, size_t n)
{
    DWORD r = 0;
    if (!ReadFile(h, buf, (DWORD)n, &r, NULL))
        return GetLastError() == ERROR_OPERATION_ABORTED ? 0 : -1;
    return (int)r;
}

/* ---------- sockets ---------- */

/* pack an IPv4 endpoint (ip + port, both network order) into one
 * Interlocked-friendly word so the rx thread can refresh the roamed
 * server endpoint without a lock */
static uint64_t sockaddr_key(const struct sockaddr_in *a)
{
    return ((uint64_t)a->sin_addr.s_addr << 16) | a->sin_port;
}

static void key_to_sockaddr(uint64_t key, struct sockaddr_in *a)
{
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = (uint32_t)(key >> 16);
    a->sin_port = (uint16_t)(key & 0xffff);
}

/* UDP socket bound to 0.0.0.0:local_port; INVALID_SOCKET = WSA error */
static SOCKET udp_bind(uint16_t local_port)
{
    SOCKET fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == INVALID_SOCKET)
        return INVALID_SOCKET;
    /* Windows fragments oversized UDP datagrams by default (the equivalent
     * of Linux IP_PMTUDISC_DONT), which is what the ~1556B outer frames
     * need; nothing to opt into. */
    int bufsz = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsz, sizeof(bufsz));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsz, sizeof(bufsz));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(local_port);
    if (bind(fd, (const struct sockaddr *)&a, sizeof(a)) < 0) {
        int e = WSAGetLastError();
        closesocket(fd);
        WSASetLastError(e);
        return INVALID_SOCKET;
    }
    return fd;
}

static void tcp_tune(SOCKET fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));
    int bufsz = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&bufsz, sizeof(bufsz));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&bufsz, sizeof(bufsz));
    /* Windows wants milliseconds, not a timeval */
    DWORD ms = 30000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof(ms));
}

/* non-blocking connect + select timeout, back to blocking; INVALID_SOCKET
 * = WSA error (timeout -> WSAETIMEDOUT) */
static SOCKET tcp_connect_to(const struct sockaddr_in *dst, int timeout_ms)
{
    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
        return INVALID_SOCKET;
    u_long nb = 1;
    ioctlsocket(fd, FIONBIO, &nb);
    if (connect(fd, (const struct sockaddr *)dst, sizeof(*dst)) < 0 &&
        WSAGetLastError() != WSAEWOULDBLOCK) {
        int e = WSAGetLastError();
        closesocket(fd);
        WSASetLastError(e);
        return INVALID_SOCKET;
    }
    fd_set w;
    FD_ZERO(&w);
    FD_SET(fd, &w);
    struct timeval tv = { .tv_sec = timeout_ms / 1000,
                          .tv_usec = (long)(timeout_ms % 1000) * 1000 };
    if (select(0, NULL, &w, NULL, &tv) <= 0 || !FD_ISSET(fd, &w)) {
        closesocket(fd);
        WSASetLastError(WSAETIMEDOUT);
        return INVALID_SOCKET;
    }
    int err = 0;
    int el = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&err, &el) < 0 || err) {
        closesocket(fd);
        WSASetLastError(err ? err : WSAECONNREFUSED);
        return INVALID_SOCKET;
    }
    nb = 0;   /* back to blocking for the pump loop */
    ioctlsocket(fd, FIONBIO, &nb);
    tcp_tune(fd);
    return fd;
}

/* ---------- TCP stream framing (same wire format as common.c) ---------- */

struct stream_rx {
    uint8_t *buf;   /* caller-provided, >= 2 + HDR_LEN + MAX_FRAME */
    size_t   have;  /* bytes buffered so far */
    size_t   need;  /* bytes wanted for the current part */
    int      hdr;   /* 1 = reading the 2-byte length, 0 = the message */
};

static void stream_rx_init(struct stream_rx *rx, uint8_t *buf)
{
    rx->buf = buf;
    rx->have = 0;
    rx->need = 2;
    rx->hdr = 1;
}

static void stream_rx_next(struct stream_rx *rx)
{
    rx->have = 0;
    rx->need = 2;
    rx->hdr = 1;
}

/* 1 = message at buf[2..have), 0 = need more, -1 = dead */
static int stream_rx_feed(struct stream_rx *rx, SOCKET fd)
{
    for (;;) {
        while (rx->have < rx->need) {
            int r = recv(fd, (char *)rx->buf + rx->have,
                         (int)(rx->need - rx->have), 0);
            if (r == 0) {           /* orderly close: connection over */
                WSASetLastError(WSAECONNRESET);
                return -1;
            }
            if (r < 0) {
                int e = WSAGetLastError();
                if (e == WSAEINTR || e == WSAEWOULDBLOCK)
                    return 0;
                return -1;
            }
            rx->have += (size_t)r;
        }
        if (rx->hdr) {
            size_t len = ((size_t)rx->buf[0] << 8) | rx->buf[1];
            if (len < 1) {
                WSASetLastError(WSAECONNRESET);
                return -1;
            }
            rx->need = 2 + len;
            rx->hdr = 0;
            continue;
        }
        return 1;
    }
}

/* ---------- pump state (lock-free except the tcp writer mutex) ---------- */

struct sh {
    struct cfg *cfg;
    HANDLE tfd;                /* tap device */
    SOCKET xfd;                /* transport socket (udp or tcp) */
    int is_tcp;
    HANDLE wake;               /* manual-reset: link death / Ctrl-C */
    CRITICAL_SECTION tcp_tx;   /* serializes the two tcp writers */
    volatile LONG64 peer_k;    /* udp: current server endpoint */
    volatile LONG dead;
};

static void mark_dead(struct sh *s)
{
    if (InterlockedExchange(&s->dead, 1) == 0)
        SetEvent(s->wake);
}

/* length header + payload in ONE WSASend (like sendmsg on Linux), under a
 * mutex: Windows promises nothing about concurrent stream writes */
static int stream_send_msg(struct sh *s, const uint8_t *msg, size_t len)
{
    if (len < 1 || len > 0xffff) {
        WSASetLastError(WSAEMSGSIZE);
        return -1;
    }
    uint8_t hdr[2] = { (uint8_t)(len >> 8), (uint8_t)(len & 0xff) };
    WSABUF part[2] = {
        { 2,           (char *)hdr },
        { (DWORD)len,  (char *)msg },
    };
    int rc = 0;

    EnterCriticalSection(&s->tcp_tx);
    size_t total = 2 + len, off = 0;
    int idx = 0;
    while (total > 0) {
        WSABUF iov[2];
        DWORD niov = 0;
        if (idx < 2) {
            iov[niov].len = (ULONG)(part[idx].len - off);
            iov[niov].buf = part[idx].buf + off;
            niov++;
            if (idx + 1 < 2)
                iov[niov++] = part[idx + 1];
        }
        DWORD sent = 0;
        if (WSASend(s->xfd, iov, niov, &sent, 0, NULL, NULL) == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEINTR)
                continue;
            WSASetLastError(e);
            rc = -1;
            break;
        }
        if (sent == 0) {
            WSASetLastError(WSAECONNABORTED);
            rc = -1;
            break;
        }
        total -= sent;
        size_t adv = sent;
        while (adv > 0 && idx < 2) {
            size_t rem = part[idx].len - off;
            if (adv < rem) {
                off += adv;
                adv = 0;
            } else {
                adv -= rem;
                idx++;
                off = 0;
            }
        }
    }
    LeaveCriticalSection(&s->tcp_tx);
    return rc;
}

static void rx_to_tap(struct sh *s, const uint8_t *frame, size_t flen)
{
    if (tap_write_frame(s->tfd, frame, flen) < 0) {
        DWORD e = GetLastError();
        logv("tap write: %s", werr(e));
    } else {
        logv("net->tap %lu bytes", (unsigned long)flen);
        if (g_verbose)
            hexdump(frame, flen, 24);
    }
}

/* ---- rx: transport -> tap (blocks in recv; udp also refreshes the peer) -- */

static void *rx_udp_thread(void *arg)
{
    struct sh *s = arg;
    uint8_t buf[HDR_LEN + MAX_FRAME];

    while (!g_stop && !s->dead) {
        struct sockaddr_in from;
        int flen = sizeof(from);
        int r = recvfrom(s->xfd, (char *)buf, (int)sizeof(buf), 0,
                         (struct sockaddr *)&from, &flen);
        if (r < 0) {
            int e = WSAGetLastError();
            if (e == WSAEINTR)
                continue;
            logmsg("recvfrom udp: %s", werr((DWORD)e));
            break;
        }
        if (r < 1)
            continue;   /* socket closed */
        uint64_t k = sockaddr_key(&from);
        if (k != (uint64_t)InterlockedCompareExchange64(&s->peer_k, 0, 0)) {
            InterlockedExchange64(&s->peer_k, (LONG64)k);
            logmsg("server endpoint updated: %s:%d",
                   inet_ntoa(from.sin_addr), ntohs(from.sin_port));
        }
        if (buf[0] == A2TP_TYPE_DATA && r > HDR_LEN + 14)
            rx_to_tap(s, buf + HDR_LEN, (size_t)r - HDR_LEN);
        else if (buf[0] != A2TP_TYPE_KEEPALIVE)
            logv("bad message type 0x%02x", buf[0]);
    }
    mark_dead(s);
    return NULL;
}

static void *rx_tcp_thread(void *arg)
{
    struct sh *s = arg;
    uint8_t buf[2 + HDR_LEN + MAX_FRAME];   /* [len(2)][type][frame] */
    struct stream_rx rx;
    stream_rx_init(&rx, buf);

    while (!g_stop && !s->dead) {
        int rc = stream_rx_feed(&rx, s->xfd);   /* blocks until a message */
        if (rc < 0)
            break;                              /* EOF / reset / bad frame */
        if (rc == 0)
            continue;
        uint8_t *msg = rx.buf + 2;
        size_t mlen = rx.have - 2;
        if (msg[0] == A2TP_TYPE_DATA && mlen > HDR_LEN + 14)
            rx_to_tap(s, msg + HDR_LEN, mlen - HDR_LEN);
        else if (!(mlen == 1 && msg[0] == A2TP_TYPE_KEEPALIVE))
            logv("bad message (type 0x%02x, %lu bytes)",
                 msg[0], (unsigned long)mlen);
        stream_rx_next(&rx);
    }
    mark_dead(s);
    return NULL;
}

/* ---- tx: tap -> transport (blocks in ReadFile; one send per frame) ------- */

static void *tx_udp_thread(void *arg)
{
    struct sh *s = arg;
    uint8_t buf[HDR_LEN + MAX_FRAME];

    while (!g_stop && !s->dead) {
        int r = tap_read_frame(s->tfd, buf + HDR_LEN, MAX_FRAME);
        if (r < 0) {
            DWORD e = GetLastError();
            logmsg("tap read: %s", werr(e));
            break;
        }
        if (r == 0)
            break;   /* aborted: teardown */
        buf[0] = A2TP_TYPE_DATA;
        struct sockaddr_in peer;
        key_to_sockaddr((uint64_t)InterlockedCompareExchange64(&s->peer_k, 0, 0),
                        &peer);
        if (sendto(s->xfd, (const char *)buf, r + HDR_LEN, 0,
                   (const struct sockaddr *)&peer, sizeof(peer)) < 0)
            logv("send: %s", werr((DWORD)WSAGetLastError()));
        else {
            logv("tap->net %d bytes", r);
            if (g_verbose)
                hexdump(buf + HDR_LEN, (size_t)r, 24);
        }
    }
    mark_dead(s);
    return NULL;
}

static void *tx_tcp_thread(void *arg)
{
    struct sh *s = arg;
    uint8_t buf[2 + HDR_LEN + MAX_FRAME];   /* [len(2)][type][frame] */

    while (!g_stop && !s->dead) {
        int r = tap_read_frame(s->tfd, buf + 2 + HDR_LEN, MAX_FRAME);
        if (r < 0) {
            DWORD e = GetLastError();
            logmsg("tap read: %s", werr(e));
            break;
        }
        if (r == 0)
            break;   /* aborted: teardown */
        buf[2] = A2TP_TYPE_DATA;
        if (stream_send_msg(s, buf + 2, HDR_LEN + (size_t)r) < 0) {
            logv("send failed: %s", werr((DWORD)WSAGetLastError()));
            break;   /* connection is gone */
        }
        logv("tap->net %d bytes", r);
        if (g_verbose)
            hexdump(buf + 2 + HDR_LEN, (size_t)r, 24);
    }
    mark_dead(s);
    return NULL;
}

/* ---- keepalive: owns the liveness timer (waits on the wake event) -------- */

static void keepalive_send(struct sh *s)
{
    uint8_t ka = A2TP_TYPE_KEEPALIVE;
    if (s->is_tcp) {
        if (stream_send_msg(s, &ka, 1) < 0) {
            logv("keepalive send: %s", werr((DWORD)WSAGetLastError()));
            mark_dead(s);
        }
    } else {
        struct sockaddr_in peer;
        key_to_sockaddr((uint64_t)InterlockedCompareExchange64(&s->peer_k, 0, 0),
                        &peer);
        if (sendto(s->xfd, (const char *)&ka, 1, 0,
                   (const struct sockaddr *)&peer, sizeof(peer)) < 0)
            logv("keepalive send: %s", werr((DWORD)WSAGetLastError()));
    }
}

static void *keepalive_thread(void *arg)
{
    struct sh *s = arg;
    int64_t next = now_ms();   /* first one right away: server learns us */

    while (!g_stop && !s->dead) {
        int64_t now = now_ms();
        if (now >= next) {
            keepalive_send(s);
            next = now + s->cfg->keepalive_ms;
        }
        int64_t ms = next - now_ms();
        if (ms < 0)
            ms = 0;
        if (ms > 1000)
            ms = 1000;   /* cap the wait so teardown never waits long */
        if (ms > 0 &&
            WaitForSingleObject(s->wake, (DWORD)ms) == WAIT_OBJECT_0)
            break;   /* link dead or Ctrl-C */
    }
    return NULL;
}

/* ---- lifecycle: main blocks here until a pump dies or Ctrl-C ------------ */

static void main_wait(struct sh *s)
{
    while (!g_stop && !s->dead)
        WaitForSingleObject(s->wake, INFINITE);
}

/* wake both pumps the Windows way: closesocket breaks recv, CancelIoEx
 * breaks the blocked ReadFile on the TAP handle */
static void pump_teardown(struct sh *s, pthread_t rx, pthread_t tx, pthread_t ka)
{
    closesocket(s->xfd);
    CancelIoEx(s->tfd, NULL);
    pthread_join(rx, NULL);
    pthread_join(tx, NULL);
    if (ka)
        pthread_join(ka, NULL);   /* leaves within <= 1 s on its own */
}

static int run_udp(struct cfg *cfg, HANDLE tfd, HANDLE wake)
{
    SOCKET ufd = udp_bind(cfg->local_port);
    if (ufd == INVALID_SOCKET)
        die("bind udp %d: %s", cfg->local_port, werr((DWORD)WSAGetLastError()));

    struct sockaddr_in local;
    int llen = sizeof(local);
    getsockname(ufd, (struct sockaddr *)&local, &llen);
    logmsg("udp local %s:%d, keepalive %lds", inet_ntoa(local.sin_addr),
           ntohs(local.sin_port),
           (long)(cfg->keepalive_ms / 1000));

    struct sh s;
    memset(&s, 0, sizeof(s));
    s.cfg = cfg;
    s.tfd = tfd;
    s.xfd = ufd;
    s.wake = wake;
    s.peer_k = (LONG64)sockaddr_key(&cfg->srv);
    InitializeCriticalSection(&s.tcp_tx);

    pthread_t rx, tx, ka = 0;
    if (pthread_create(&rx, NULL, rx_udp_thread, &s) ||
        pthread_create(&tx, NULL, tx_udp_thread, &s) ||
        (cfg->keepalive_ms > 0 &&
         pthread_create(&ka, NULL, keepalive_thread, &s)))
        die("pthread_create");

    main_wait(&s);
    pump_teardown(&s, rx, tx, ka);
    DeleteCriticalSection(&s.tcp_tx);
    logmsg("shutting down");
    return 0;
}

/* reconnect pause that Ctrl-C can interrupt */
static void sleep_capped(HANDLE wake, int ms)
{
    for (int left = ms; left > 0 && !g_stop; left -= 100)
        WaitForSingleObject(wake, left >= 100 ? 100 : (DWORD)left);
}

static int run_tcp(struct cfg *cfg, HANDLE tfd, HANDLE wake)
{
    struct sh s;
    memset(&s, 0, sizeof(s));
    s.cfg = cfg;
    s.tfd = tfd;
    s.wake = wake;
    s.is_tcp = 1;
    InitializeCriticalSection(&s.tcp_tx);

    while (!g_stop) {
        logmsg("connecting to %s:%d (tcp)", inet_ntoa(cfg->srv.sin_addr),
               ntohs(cfg->srv.sin_port));
        SOCKET cfd = tcp_connect_to(&cfg->srv, 5000);
        if (cfd == INVALID_SOCKET) {
            logmsg("connect failed: %s, retrying",
                   werr((DWORD)WSAGetLastError()));
            sleep_capped(wake, 3000);
            continue;
        }

        s.xfd = cfd;
        s.dead = 0;
        ResetEvent(wake);   /* fresh connection, fresh watch */

        pthread_t rx, tx, ka = 0;
        if (pthread_create(&rx, NULL, rx_tcp_thread, &s) ||
            pthread_create(&tx, NULL, tx_tcp_thread, &s) ||
            (cfg->keepalive_ms > 0 &&
             pthread_create(&ka, NULL, keepalive_thread, &s)))
            die("pthread_create");   /* process exits, threads die with it */

        main_wait(&s);
        int stopped = g_stop;
        pump_teardown(&s, rx, tx, ka);
        if (stopped)
            break;
        logmsg("tcp connection lost, reconnecting");
        sleep_capped(wake, 3000);
    }

    DeleteCriticalSection(&s.tcp_tx);
    logmsg("shutting down");
    return 0;
}

/* ---------- console Ctrl-C (the Windows "signal") ---------- */

static HANDLE g_wake;

static BOOL WINAPI ctrl_handler(DWORD type)
{
    (void)type;
    InterlockedExchange(&g_stop, 1);
    if (g_wake)
        SetEvent(g_wake);
    return TRUE;
}

/* ---------- command line ---------- */

static void usage(FILE *out)
{
    fprintf(out,
        "usage: a2tp-cli -s <server_ip[:port]> [options]   (Windows, tap-windows6)\n"
        "\n"
        "  -s, --server <ip[:port]>  tunnel server (default port %d)\n"
        "  -p, --port <port>         local UDP port (default %d, 0 = ephemeral;\n"
        "                            udp mode only, tcp uses an ephemeral port)\n"
        "  -t, --tap <name|guid>     TAP adapter: connection name or GUID\n"
        "                            (default: first %s adapter found)\n"
        "      --list                list TAP adapters and exit\n"
        "      --tcp                 framed TCP stream instead of UDP: kernel\n"
        "                            congestion control and retransmission; the\n"
        "                            server must be started with --tcp too\n"
        "      --up                  accepted for compatibility; media status is\n"
        "                            always set connected\n"
        "      --mac <aa:bb:..>      set the adapter MAC (persistent registry\n"
        "                            value; the adapter is bounced once via netsh\n"
        "                            when it changes, e.g. to clone the server NIC)\n"
        "      --mtu <n>             set the adapter MTU (persistent, like --mac)\n"
        "      --ip <ip>             set a static IPv4 address via netsh\n"
        "      --mask <m>            netmask for --ip, e.g. 255.255.255.0\n"
        "      --gw <ip>             default gateway for --ip (optional)\n"
        "      --keepalive <s>       keepalive interval (default 10, 0 = off)\n"
        "  -v, --verbose             per-packet logging\n"
        "  -h, --help                this help\n"
        "\n"
        "needs the tap-windows6 driver (bundled with OpenVPN) and an elevated\n"
        "console.  Without --ip configure the address yourself, e.g.:\n"
        "  netsh interface ip set address name=\"<adapter>\" \\\n"
        "      static 192.168.1.123 255.255.255.0\n",
        A2TP_UDP_PORT, A2TP_UDP_PORT, TAP_COMPONENT_ID);
}

/* option value: whatever follows '=', else the next argv (consumed) */
static const char *optval(int argc, char **argv, int *i)
{
    const char *eq = strchr(argv[*i], '=');

    if (eq)
        return eq + 1;
    if (*i + 1 >= argc)
        return NULL;
    return argv[++*i];
}

int main(int argc, char **argv)
{
    struct cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.local_port = A2TP_UDP_PORT;
    cfg.keepalive_ms = 10000;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i], *v;
        char name[64];   /* option name without any "=value" suffix */
        snprintf(name, sizeof(name), "%s", a);
        char *eq = strchr(name, '=');
        if (eq)
            *eq = '\0';

        if (!strcmp(name, "-h") || !strcmp(name, "--help")) {
            usage(stdout);
            return 0;
        } else if (!strcmp(name, "-v") || !strcmp(name, "--verbose"))
            g_verbose = 1;
        else if (!strcmp(name, "--tcp"))
            cfg.tcp = 1;
        else if (!strcmp(name, "-U") || !strcmp(name, "--up"))
            ;   /* media status is always set connected */
        else if (!strcmp(name, "--list"))
            cfg.list_only = 1;
        else if (!strcmp(name, "-s") || !strcmp(name, "--server")) {
            v = optval(argc, argv, &i);
            if (!v || parse_ip_port(v, A2TP_UDP_PORT, &cfg.srv) < 0)
                die("-s: expect ip[:port]");
            cfg.have_srv = 1;
        } else if (!strcmp(name, "-p") || !strcmp(name, "--port")) {
            v = optval(argc, argv, &i);
            if (!v || atoi(v) < 0 || atoi(v) > 65535)
                die("-p: expect 0..65535");
            cfg.local_port = (uint16_t)atoi(v);
        } else if (!strcmp(name, "-t") || !strcmp(name, "--tap")) {
            v = optval(argc, argv, &i);
            if (!v || !*v)
                die("-t: expect an adapter name or GUID");
            cfg.tap = v;
        } else if (!strcmp(name, "--mac")) {
            v = optval(argc, argv, &i);
            if (!v || parse_mac(v, cfg.mac) < 0)
                die("--mac: expect aa:bb:cc:dd:ee:ff");
            cfg.have_mac = 1;
        } else if (!strcmp(name, "--mtu")) {
            v = optval(argc, argv, &i);
            if (!v || atoi(v) < 576 || atoi(v) > 65536)
                die("--mtu: expect 576..65536");
            cfg.mtu = atoi(v);
        } else if (!strcmp(name, "--ip")) {
            v = optval(argc, argv, &i);
            if (!v || !*v)
                die("--ip: expect an IPv4 address");
            cfg.ip = v;
        } else if (!strcmp(name, "--mask")) {
            v = optval(argc, argv, &i);
            if (!v || !*v)
                die("--mask: expect a netmask, e.g. 255.255.255.0");
            cfg.mask = v;
        } else if (!strcmp(name, "--gw")) {
            v = optval(argc, argv, &i);
            if (!v || !*v)
                die("--gw: expect an IPv4 address");
            cfg.gw = v;
        } else if (!strcmp(name, "-k") || !strcmp(name, "--keepalive")) {
            v = optval(argc, argv, &i);
            if (!v || atoi(v) < 0)
                die("--keepalive: expect >= 0");
            cfg.keepalive_ms = atoi(v) * 1000;
        } else {
            fprintf(stderr, "unknown option: %s\n\n", a);
            usage(stderr);
            return 1;
        }
    }

    if (cfg.list_only) {
        tap_list_print();
        return 0;
    }
    if (!cfg.have_srv) {
        usage(stderr);
        return 1;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) < 0)
        die("WSAStartup");

    g_wake = CreateEvent(NULL, TRUE /*manual-reset*/, FALSE, NULL);
    if (!g_wake)
        die("CreateEvent");
    if (!SetConsoleCtrlHandler(ctrl_handler, TRUE))
        logmsg("SetConsoleCtrlHandler failed: Ctrl-C will still kill us");

    /* ---- adapter: pick, apply persistent config, open, plug the cable --- */

    struct tap_adapter ad;
    int count = 0;
    if (tap_pick(&cfg, &ad, &count) < 0) {
        if (count == 0)
            die("no TAP adapter (ComponentId %s) on this machine;\n"
                "install the tap-windows6 driver (bundled with OpenVPN)",
                TAP_COMPONENT_ID);
        tap_list_print();
        die("adapter \"%s\" not found (see list above)", cfg.tap);
    }
    if (tap_apply_mac_mtu(&cfg, &ad) < 0)
        die("configuring %s failed (need Administrator?)", ad.name);

    HANDLE tfd = tap_open_dev(ad.path);

    ULONG ver[3] = { 0, 0, 0 };
    if (tap_ioctl(tfd, TAP_IOCTL_GET_VERSION, NULL, 0,
                  ver, sizeof(ver)) == 0)
        logv("tap-windows driver %lu.%lu", ver[0], ver[1]);

    ULONG drv_mtu = 0;
    int have_drv_mtu =
        tap_ioctl(tfd, TAP_IOCTL_GET_MTU, NULL, 0,
                  &drv_mtu, sizeof(drv_mtu)) == 0;
    if (cfg.mtu > 0 && have_drv_mtu && (int)drv_mtu != cfg.mtu)
        logmsg("warning: driver MTU is %lu, not %d "
               "(tap-windows6 may ignore the MTU registry value)",
               drv_mtu, cfg.mtu);

    uint8_t mac[6] = { 0 };
    tap_get_mac(ad.guid, mac);
    tap_media_status(tfd, 1);   /* "cable in": the stack starts using it */

    if (cfg.ip) {
        if (!cfg.mask)
            die("--ip needs --mask");
        char args[300];
        if (cfg.gw)
            snprintf(args, sizeof(args),
                     "interface ip set address name=\"%s\" static %s %s %s 1",
                     ad.name, cfg.ip, cfg.mask, cfg.gw);
        else
            snprintf(args, sizeof(args),
                     "interface ip set address name=\"%s\" static %s %s",
                     ad.name, cfg.ip, cfg.mask);
        if (sh_netsh(args) < 0)
            die("netsh static address failed (need Administrator?)");
    }

    logmsg("a2tp-cli tap \"%s\" (mac %02x:%02x:%02x:%02x:%02x:%02x, mtu %d), "
           "%s, server %s:%d",
           ad.name, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           have_drv_mtu ? (int)drv_mtu : 0,
           cfg.tcp ? "tcp" : "udp",
           inet_ntoa(cfg.srv.sin_addr), ntohs(cfg.srv.sin_port));
    if (!cfg.ip)
        logv("hint: address not configured; netsh interface ip set address "
             "name=\"%s\" static <ip> <mask>", ad.name);

    /* one dispatch at startup: the pump threads are transport-specific */
    int rc = cfg.tcp ? run_tcp(&cfg, tfd, g_wake) : run_udp(&cfg, tfd, g_wake);

    tap_media_status(tfd, 0);   /* "cable out": a clean disconnect */
    CloseHandle(tfd);
    WSACleanup();
    return rc;
}



