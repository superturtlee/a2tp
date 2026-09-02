# A2tp — another layer2 transport

> [!CAUTION]
> **法律声明与注意事项（使用前必读）**
>
> **法律声明**：本项目仅供网络技术研究、学习，以及在**自有或已授权**的设备与网络内
> 做二层透传实验。
>
> - **不得将本项目用于非法跨境通信（即"翻墙"）**；
> - **不得违反云服务商的服务条款与网络使用规定**。
>
> 因不当使用产生的一切后果由使用者自行承担。
>
> **注意事项**：
>
> 1. **法律**：使用前请了解并遵守所在地区法律法规（包括但不限于计算机信息网络
>    国际联网管理、网络安全等相关规定）；部署在云服务器上时须同时遵守云服务商的
>    相关规定。
> 2. **无认证、无加密**：任何知道 server 端口的人都可能注入帧或截获镜像流量，不要
>    把端口直接暴露在不可信网络。在无法套 WireGuard/IPsec 的情况下，至少采取以下
>    缓解措施之一：
>    - **固定 client**：server 用 `--peer <ip:port>` 锁定唯一对端，并用防火墙限制
>      隧道端口的来源地址；
>    - **隧道包裹**：用 wstunnel 等加密隧道包裹 a2tp 流量，server 侧
>      `--bind 127.0.0.1` 只监听本机，使 a2tp 端口不直接暴露公网。
>    - 路径上的任何中间路由器/网关都可以审查（看穿隧道内全部流量）、修改（注入/
>      篡改/重放内层帧，接收端无校验，照单全收注入网卡）隧道数据包；因此**必须保证
>      server 到物理网关的互联网链路可信**（如两端在同一内网、或链路本身受控），
>      否则请套 WireGuard/IPsec，或退一步**在承载的内层应用使用 SSL/TLS**（内层流量
>      自身加密，中间设备只能看到流量形态而非内容）。

**A2tp**（**a**nother **l2tp**）：参照 Linux 内核
`net/l2tp`（L2TPv3 over UDP 数据面）的思路实现的 L2 透传，一对端点把 server 上的
一块网卡完整"搬"到 client 本地（server 网卡镜像 / client TAP 克隆）。

**同一套线协议（UDP 1702，`type(1B)+以太网帧`）有两种实现，可任意交叉对接**：

| 实现 | 数据面 | 配置面 | 适用 |
|---|---|---|---|
| 用户态（`a2tp-srv`/`a2tp-cli`） | AF_PACKET + TAP，每帧 2 syscall | 命令行参数 | 调试/对照/回退，无需 root 内核模块 |
| **内核模块（`a2tp.ko` + `a2tpctl`）** | rx_handler 镜像 + rtnl netdev，全程不出内核 | genl + rtnl_link | 生产：吞吐/延迟 + IPv6 + 叠 wg/IPsec |

内核版文档（架构、a2tpctl 参考、IPv6、可靠性契约、权限矩阵、wg/IPsec 叠加、
部署约束）：**[docs/kernel.md](docs/kernel.md)**。

用户态版架构：

```
                server 主机                                 client 主机
        ┌────────────────────────────┐            ┌──────────────────────────┐
LAN ────┤ eth0 (混杂模式)             │            │  tap a2tp0               │
        │   │▲                       │            │   ▲│                     │
        │   ││ AF_PACKET             │   UDP      │   ││                     │
        │   ▼│ (镜像/注入)            │ ────────►  │   ││ TAP fd              │
        │  a2tp-srv ◄────────────────┼────────────┼── a2tp-cli               │
        └────────────────────────────┘  :1702     └──────────────────────────┘
```

- **server（a2tp-srv）**：把网卡设为混杂模式（`PACKET_MR_PROMISC`，tcpdump 同款做法），
  收到的**每一个 L2 帧**原样封进 UDP 发给 client；client 发来的帧**原样注入**网卡
  （AF_PACKET 裸发送）→ 双向 L2 透传。全程不创建、不依赖任何 bridge，直接接管网卡。
- **client（a2tp-cli）**：创建 TAP 网卡，镜像帧写入 tap、tap 发出的帧送回 server 注入
  → 本地得到 server 网卡的一个"克隆"。tap 默认置 UP + 混杂，非本机 MAC 的单播镜像帧
  也能进入本机协议栈（可用于嗅探/接管）。

## 与内核 L2TPv3-UDP 的对照

| | 内核 L2TP（`ip l2tp add`） | 本项目 |
|---|---|---|
| 承载 | UDP 1701（`L2TP_ENCAPTYPE_UDP`） | UDP 1702（可改；默认避开内核 L2TP 的 1701） |
| 数据面 | `SessionID(4)+Cookie(0/4/8)+[L2 sublayer]+L2帧` | `type(1B)+L2帧` |
| 配置面 | netlink 静态配置 tunnel/session | 命令行参数，无 session 概念 |
| 对端寻址 | tunnel socket 固定 connect | **每包学习/刷新对端 ip:port（NAT 漫游）** |
| 认证/加密 | — | —（无认证无加密，限可信网络） |

封装格式（刻意简化，不与上游互通）：

```
UDP payload:  u8 type   0x01 = data（后跟一个完整以太网帧，含 VLAN tag）
                        0x02 = keepalive（无 payload，仅刷新对端地址）
```

## 编译与运行

```bash
make                # 用户态：a2tp-srv a2tp-cli（无第三方依赖，只需 glibc）
make kmod           # 内核模块：kernel/a2tp.ko（需要内核 headers）
make a2tpctl        # 内核版控制工具（零依赖）

# ── 内核版（生产推荐，详见 docs/kernel.md）──────────────────────────
sudo modprobe udp_tunnel && sudo modprobe ip6_udp_tunnel
sudo insmod kernel/a2tp.ko
sudo ./a2tpctl srv add -i eth0                 # server：接管 eth0（CAP_NET_ADMIN）
sudo ./a2tpctl cli add a2tp0 remote <server_ip>   # client：本地出现 a2tp0
sudo ip link set a2tp0 up && sudo ip addr add 192.168.1.123/24 dev a2tp0

# ── 用户态版（对照/回退）──────────────────────────────────────────
# server：接管 eth0（需要 root/CAP_NET_RAW）
sudo ./a2tp-srv -i eth0

# client：连接 server，本地出现克隆网卡 a2tp0（需要 root/CAP_NET_ADMIN）
sudo ./a2tp-cli -s <server_ip> --tap a2tp0
sudo ip addr add 192.168.1.123/24 dev a2tp0     # 地址/路由用 ip(8) 配置
```

"克隆"示例——让 client 与 server 网卡同 MAC 同网段直接顶替使用：

```bash
sudo ./a2tp-cli -s <server_ip> --tap a2tp0 \
     --mac $(cat /sys/class/net/eth0/address)   # 复制 server 网卡 MAC
```

### a2tp-srv 选项

| 选项 | 说明 |
|---|---|
| `-i, --iface <name>` | 被接管的网卡（混杂抓包 + 注入） |
| `-p, --port <port>` | UDP 监听端口，默认 1702 |
| `-b, --bind <ip>` | 只监听该本地地址（默认 0.0.0.0 所有地址；如 `--bind 127.0.0.1` 仅服务本机/同 netns 的 client） |
| `--peer <ip:port>` | 固定对端（只收该地址的包）；默认动态：**每包刷新 peer**，支持 NAT/漫游 |
| `--peer-timeout <s>` | 对端静默 N 秒后暂停镜像，待下一包重新学习（默认 30，0=不超时） |
| `--no-self-filter` | 关闭"隧道自身 UDP 流量"过滤（默认过滤，防止隧道套隧道回声） |
| `--filter-ip <ip[,ip..]>` | **多 IP 网卡模式**：只镜像 IPv4 目的地址为这些 IP 的帧（client 接管、已从本机协议栈删除的 IP；可重复/逗号分隔）。ARP 全部透传，其余帧留在本机协议栈。默认全镜像不过滤 |
| `--keep-offloads` | 不动网卡的 tso/gso/gro（默认自动关闭、退出时恢复） |
| `-v` | 逐帧日志（前 24 字节 hexdump） |

### a2tp-cli 选项

| 选项 | 说明 |
|---|---|
| `-s, --server <ip[:port]>` | server 地址（默认端口 1702） |
| `-p, --port <port>` | 本地 UDP 端口（默认 1702，`0`=随机；server 与 client 同机时用 0） |
| `-t, --tap <name>` | TAP 名，默认 `a2tp0` |
| `--mac <aa:bb:..>` | 设置 tap MAC（如复制 server 网卡 MAC） |
| `--mtu <n>` | 设置 MTU（IP 地址与路由不归 client 管，用 `ip addr` / `ip route` 配置） |
| `--keepalive <s>` | keepalive 间隔（默认 10s，0=关闭）。启动即发首包让 server 学到对端 |
| `-v` | 逐帧日志 |

## 设计要点

- **线程模型（全程阻塞，零轮询）**：所有泵线程都睡在 syscall 里，数据到达由内核唤醒，
  空闲时 CPU 占用为零——没有任何"试探循环"：
  - *client*：rx 线程（transport→tap，阻塞在 recv）、tx 线程（tap→transport，阻塞在
    read）、keepalive 线程（nanosleep 定时器，单次 syscall 发送）。main 只管生命周期：
    阻塞在读事件管道上，某线程死亡或信号到来才醒来做拆链。
  - *server*：rx 线程（transport→注入网卡）、main 本身即镜像泵（阻塞 recvfrom 抓包
    socket；1s 接收超时是唯一的空闲 tick，用于在网卡安静时察觉退出）。
  - **无锁**：每条消息只一次 sendto syscall（UDP 原子语义，内核 socket 锁天然串行化
    并发写者），共享状态全是原子字（对端地址打包成一个 `u64`、死亡标志）。
  - 退出路径：`shutdown()` 唤醒阻塞在 socket 读的线程，tap 的 char 设备读只能
    `pthread_cancel` 唤醒，keepalive 线程睡眠封顶 1s 自行退出；工作线程屏蔽
    SIGINT/SIGTERM，信号只由 main 处理。
- **多 IP 网卡（`--filter-ip`）**：网卡上多个 IP 时可把其中一部分"搬"给远端 client——
  先从本机协议栈删除该 IP（`ip addr del`），server 用 `--filter-ip` 只镜像目的地址为
  该 IP 的帧；其余 IP 的流量完全不受影响（AF_PACKET 只是旁路抓包，未镜像的帧协议栈
  照常处理）。**ARP 透传、server 零状态**：request 镜像给 client、client 协议栈用
  自己的 tap MAC 应答、注入回网卡——主网卡应答它保留的 IP，clone 应答它接管的 IP，
  所有权不相交故无竞争；client 离线时该 IP 不可达（语义如实），回来后路由器 STALE
  探测经隧道自愈。WiFi 上 client tap 需克隆网卡 MAC（802.11 managed 模式只交付发往
  station MAC 的单播，且注入帧的源 MAC 必须是 station MAC）。
  **完整操作手册：[docs/single-ip-takeover.md](docs/single-ip-takeover.md)**（步骤、
  验证命令、故障排查、还原）。
- **NAT 友好/漫游**：双方都从每个收到 UDP 包的源地址刷新对端（WireGuard 式）。client
  每 10s 发 keepalive 维持 NAT 映射，换网络（IP/端口变化）后隧道自动恢复。
- **同 netns 部署要 `arp_ignore=1`**：server 网卡和 client tap 若在**同一个**
  netns/主机且同网段（如 testbed、同机 loopback 用法），默认 `arp_ignore=0` 会让内核
  用 server 网卡的 MAC 代答 tap IP 的 ARP——不需要隧道就能答。平时无碍（tap 经隧道的
  正确应答后到、覆盖），但 **client 离线期间只有内核代答**，对端邻居表被污染成 server
  网卡 MAC，client 重启后回包对 tap 是 `PACKET_OTHERHOST` 而被静默丢弃且无法自愈。同
  netns 跑就 `sysctl net.ipv4.conf.all.arp_ignore=1`；server 与 tap 分属不同 netns
  （如真实跨机部署）则天然免疫。
- **防环**：① 注入用同一个 AF_PACKET socket，发送不自环，且设置
  `PACKET_IGNORE_OUTGOING` 并丢弃 `PACKET_OUTGOING`，本机流量不会被镜像回来；
  ② 镜像前过滤与隧道自身五元组匹配的 IPv4/UDP 帧，防止"隧道套隧道"回声。
- **镜像范围**：网卡**收到**的帧（含发往其他 MAC 的单播、组播、广播）。发往本机的
  单播在真实网卡上依赖混杂模式才能收到；veth 上天然全收，测试床即此拓扑。
- **Offload 与校验和（无任何用户态计算）**：
  - *校验和*全部由内核/硬件完成——client 的 tap 以 `IFF_NO_PI`（不协商
    `IFF_VNET_HDR`）+ `TUNSETOFFLOAD(0)` 打开，内核被迫软件算完校验和再交付；
    真实网卡方向由硬件在帧上线前完成。**veth 实验拓扑例外**：veth 的
    tx-checksumming 会把 `CHECKSUM_PARTIAL` 占位帧原样交给对端（AF_PACKET 抓包点
    和协议栈都会静默丢弃），必须在**流量源**`ethtool -K <if> tx off` 根治
    （testbed.sh 已内置）。
  - *tso/gso/gro*：GRO 在抓包点之前把帧合并成 64KB 超级帧——那不是线上的帧，
    且超过 UDP 单包上限 65507，TCP 过隧道会全灭。server 启动时自动关闭网卡的
    tso/gso/gro，**退出时恢复原值**（`--keep-offloads` 可保留不碰）。
- **MTU**：内层以太网帧 1514B + 外层 UDP/IP/以太网头 ≈ 1556B，超过 1500 时外层 IP
  自动分片（已设 `IP_PMTUDISC_DONT`）。对延迟敏感可在底层网络放大 MTU，或给 tap 设
  较小 MTU（如 1400）避免分片。
- **安全警告**：默认无认证、无加密，任何知道 server 端口的人都能注入帧/收到镜像
  流量，只可在可信网络使用；需要机密性/认证时套 WireGuard/IPsec 等（缓解措施见开头
  "法律声明与注意事项"）。

## 测试

内核模块的测试**一律在 QEMU 一次性 overlay VM 沙箱里跑**（宿主机从不 insmod——
早期在宿主上加载模块打崩过网络栈；沙箱 `tools/qemu-vm.sh`，首次
`fetch && bake`，VM 经 9p 挂载本仓库）：

```bash
./test/qemu.sh testbed    # T1-T10：数据面功能矩阵
./test/qemu.sh wg         # W1-W4：WireGuard 承载可靠性
./test/qemu.sh xfrm       # X1-X3：IPsec 承载
./test/qemu.sh caps       # C1-C5：CAP_NET_ADMIN × userns 权限矩阵
./test/qemu.sh sh '<cmd>' # 沙箱内任意命令
```

全部 27 项断言当前全绿（10+6+4+7）。

### testbed.sh（veth 实验室，无 bridge）— T1-T10

两个 netns 间一对 veth，server 直接接管 veth 网卡：T1 双向 ping（ARP+ICMP 全走
隧道）；T2 发往无关 MAC 的单播帧被镜像（混杂）；T3 线上 echo 恰好 3/3（无环无
风暴）；T4 client 换端口重连后 server 重学对端（NAT 漫游）；T5 `--bind 127.0.0.1`
只听环回且本机 client 可用；T6 `--filter-ip` 多 IP 过滤（被滤 IP 走隧道、其余 IP
留本机且一帧不上 tap）；T7 v6 传输（外层 UDP over v6 + NDP/ICMPv6 内层）；T8
`--filter-ip6` 地址式掩码过滤；T9 承载地址被删：流量停、实例活、恢复即续；T10
默认路由跳变（断"WiFi"换"网线"）：客户端零配置换源地址，同一 server 实例重学
对端。日志在 `/tmp/a2tp-srv.log`、`/tmp/a2tp-cli.log`。

### wg.sh（WireGuard 承载可靠性）— W1-W4

三 netns：a2tp 外层 UDP 整体跑在 wg0 里（client remote 填 server 的 wg overlay
地址）。W1 隧道过 wg 通、底层抓包只有 wg 密文无明文 udp/1702、server 学到 overlay
端点；W2 未 pin 断连（client `ip link wg0 down`）：流量停、双端实例活、恢复自愈；
W3 server pin（`-b <wg ip>`）后删该地址：镜像尝试计入 `tx_err`、实例活、恢复自愈；
W4 client pin（`local <wg ip>`）后删该地址：静默等待、恢复自愈。密钥须放在
`/etc/wireguard/` 下（Ubuntu 的 wg(8) AppArmor profile 只允许读那里的私钥）。

### xfrm.sh（IPsec 承载）— X1-X3

传输模式 ESP 保护外层：底层只见 ESP；删策略后出现明文 udp/1702（证明 X1 的断言
是真的）；隧道本身不依赖 IPsec，无策略也通。

### caps.sh（权限矩阵）— C1-C5

普通用户 / 真 root / root 剥 CAP_NET_ADMIN / userns 假 root 侵初始 netns /
userns 假 root 自建 netns。前四者 admin 操作全部 EPERM（`srv status` 保持可读），
最后一种放行（容器部署姿势）。详见 [docs/kernel.md](docs/kernel.md) 的权限模型。

## 扩展方向

- 多 client：server 端 peer 表 + session id 区分（当前单 client）
- 序列号/重排（内核 `send_seq`/`recv_seq` 的思路）
- `--mirror-tx`：把本机发出的帧也镜像出去（需对注入帧做去重）
- 内核 L2TP 互通：把头部换成 `SessionID+Cookie` 即可与 `ip l2tp add` 对接
