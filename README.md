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
>    国际联网管理、网络安全等相关规定）；部署在云服务器上时须同时遵守云服务商
>    的相关规定。
> 2. **无认证条件下的安全性**：本项目**无认证、无加密**，任何知道 server 端口的
>    人都可能注入帧或截获镜像流量，不要把端口直接暴露在不可信网络。在无法套
>    WireGuard/IPsec 的情况下，至少采取以下缓解措施之一：
>    - **固定 client**：server 用 `--peer <ip:port>` 锁定唯一对端，并用防火墙限制
>      隧道端口的来源地址；
>    - **隧道包裹**：用 wstunnel 等加密隧道包裹 a2tp 流量，server 侧
>      `--bind 127.0.0.1` 只监听本机，使 a2tp 端口不直接暴露公网。
> 3. **key 认证不是安全保证**：`--tcp --pubkey` 的挑战-应答（见"TCP 挑战认证"）
>    **只验证 client 持有授权私钥，不加密、不防篡改任何数据**——它不能替代
>    WireGuard/IPsec：
>    - **数据面全程明文**：路径上的任何中间路由器/网关都可以审查（看穿隧道内
>      全部流量）、修改（注入/篡改/重放内层帧，接收端无校验，照单全收注入网卡）
>      隧道数据包；
>    - **也不向 client 认证 server**：client 无法确认对端是真 server，中间人可以
>      整体冒充；
>    - 因此**必须保证 server 到物理网关的互联网链路可信**（如两端在同一内网、
>      或链路本身受控），否则请套 WireGuard/IPsec，或退一步**在承载的内层应用
>      使用 SSL/TLS**（内层流量自身加密，中间设备只能看到流量形态而非内容）。

**A2tp**（**a**nother **l2tp**）：参照 Linux 内核
`net/l2tp`（L2TPv3 over UDP 数据面）的思路实现的用户态 C 程序，一对进程把
server 上的一块网卡完整"搬"到 client 本地（server 网卡镜像 / client TAP 克隆）：

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
| 认证/加密 | — | TCP 挑战-应答（ssh ed25519 密钥，见下文）；数据面不加密 |

封装格式（刻意简化，不与上游互通）：

```
UDP payload:  u8 type   0x01 = data（后跟一个完整以太网帧，含 VLAN tag）
                        0x02 = keepalive（无 payload，仅刷新对端地址）

--tcp 模式下同一载荷改走 TCP 流，为字节流加帧界：
TCP stream:   u16 be N，随后 N 字节（同样 u8 type + 载荷，N ≥ 1）

--tcp + --pubkey 时，连接建立后先走挑战-应答（见"TCP 挑战认证"）：
              0x03 = challenge（payload = u64 be unix-ms + u32 be 随机，共 12B）
              0x04 = response（payload = 64B ed25519 签名，覆盖上述 12B）
```

## 编译与运行

```bash
make                # 产出 a2tp-srv a2tp-cli（依赖 OpenSSL libcrypto，需 libssl-dev）
make check          # 认证模块自测（密钥解析 + 签名验签 + 与 openssl CLI 双向互操作）
make a2tp-cli.exe   # 另有 Windows 客户端（见下文"Windows 客户端"）

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
| `--tcp` | 改用 TCP 流承载（client 也须 `--tcp`）：内核负责拥塞控制与重传；单连接，断开后自动重新 accept。`--peer`/`--peer-timeout` 仅 UDP 模式有效 |
| `--peer <ip:port>` | 固定对端（只收该地址的包）；默认动态：**每包刷新 peer**，支持 NAT/漫游 |
| `--peer-timeout <s>` | 对端静默 N 秒后暂停镜像，待下一包重新学习（默认 30，0=不超时） |
| `--no-self-filter` | 关闭"隧道自身 UDP 流量"过滤（默认过滤，防止隧道套隧道回声） |
| `--filter-ip <ip[,ip..]>` | **多 IP 网卡模式**：只镜像 IPv4 目的地址为这些 IP 的帧（client 接管、已从本机协议栈删除的 IP；可重复/逗号分隔）。ARP 全部透传，其余帧留在本机协议栈。默认全镜像不过滤 |
| `--keep-offloads` | 不动网卡的 tso/gso/gro（默认自动关闭、退出时恢复） |
| `--pubkey <file>` | authorized_keys 格式的 ssh-ed25519 公钥文件（每行一个，可多把）。开启后**每条 TCP 连接**都要答挑战（见"TCP 挑战认证"）；需 `--tcp` |
| `-v` | 逐帧日志（前 24 字节 hexdump） |

### a2tp-cli 选项

| 选项 | 说明 |
|---|---|
| `-s, --server <ip[:port]>` | server 地址（默认端口 1702） |
| `-p, --port <port>` | 本地 UDP 端口（默认 1702，`0`=随机；server 与 client 同机时用 0） |
| `-t, --tap <name>` | TAP 名，默认 `a2tp0` |
| `--tcp` | 改用 TCP 流承载（server 也须 `--tcp`）；断线自动重连（3s 重试）。`-p` 仅 UDP 模式有效 |
| `--mac <aa:bb:..>` | 设置 tap MAC（如复制 server 网卡 MAC） |
| `--mtu <n>` | 设置 MTU（IP 地址与路由不归 client 管，用 `ip addr` / `ip route` 配置） |
| `--keepalive <s>` | keepalive 间隔（默认 10s，0=关闭）。启动即发首包让 server 学到对端 |
| `--privatekey <file>` | ssh ed25519 私钥（openssh 格式、无口令，即 `ssh-keygen -t ed25519` 产物）用于应答 server 的挑战；需 `--tcp` |
| `-v` | 逐帧日志 |

## TCP 挑战认证

`--tcp` 模式下可用 ssh 格式 ed25519 密钥做挑战-应答认证（仅 Linux 端；UDP 模式
无法安全承载握手，两侧都会拒绝密钥选项）：

```bash
ssh-keygen -t ed25519 -f a2tp_key -N ''            # 生成密钥对
sudo ./a2tp-srv -i eth0 --tcp --pubkey a2tp_key.pub # server：authorized_keys 风格，可放多把公钥
sudo ./a2tp-cli -s <server_ip> --tcp --privatekey a2tp_key
```

流程：server accept 后立刻发送 `0x03` 挑战——**u64 unix 毫秒时间戳 + u32 随机数
共 96 bit**；client 必须在 10 秒内回 `0x04`：用私钥对这 12 字节做的 ed25519 签名
（64 字节）。签名能被任一授权公钥验过，隧道才起；否则断开。密码学全部由
OpenSSL libcrypto 完成（EVP ed25519 + `RAND_bytes`），本项目只解析 ssh 密钥容器。

**防重放**：应答只对"签过字的那 12 字节"有效。重放一条录下的应答，需要 server
恰好再次发出同一个挑战——u64 毫秒时间戳随时间单调推进，跨时间重发在构造上不可
能；只剩同一毫秒内 u32 随机数碰撞（概率 2⁻³²），且 server 验证时还检查挑战时间
戳未漂出 30 秒新鲜窗口（纵深防御，防伪造过期挑战签名）。每次连接挑战都不同，
录制的应答永远验不过第二次。

无密钥的 server（没给 `--pubkey`）不发起挑战；带 `--privatekey` 的 client 等 2 秒
没有挑战就照常无认证建隧道（日志会注明），同一把 client 密钥两种 server 都能用。
带公钥的 server 也会拒绝没有私钥的 client（含 Windows 客户端——它尚未实现应答）。
认证只证明"client 持有授权私钥"，不加密数据面、也不向 client 认证 server。

## Windows 客户端（a2tp-cli.exe）

`src/client-win.c` 是 Windows 原生移植：线格式、UDP/TCP 双传输、keepalive、
NAT 漫游与 Linux 版完全一致，直接对接同一个 Linux `a2tp-srv`。L2 后端是
**tap-windows6** 驱动（OpenVPN 自带，ComponentId `tap0901`）。

```bash
make a2tp-cli.exe    # 交叉编译，需 x86_64-w64-mingw32-gcc；-static 无 DLL 依赖
```

以管理员身份在 Windows 控制台运行：

```bat
a2tp-cli.exe --list                       & REM 列出 TAP 适配器
a2tp-cli.exe -s <server_ip> -t "a2tp-tap0" --mac aa:bb:cc:dd:ee:ff ^
             --ip 192.168.1.123 --mask 255.255.255.0
a2tp-cli.exe -s <server_ip> --tcp         & REM TCP 模式，断线自动重连
```

| Windows 专属选项 | 说明 |
|---|---|
| `-t <name\|guid>` | 按连接名或 GUID 选适配器（默认第一个 tap0901 适配器） |
| `--list` | 列出 TAP 适配器后退出 |
| `--mac` / `--mtu` | 写入注册表持久值；有变化时自动用 netsh 弹跳适配器一次使其生效 |
| `--ip` / `--mask` / `--gw` | 便捷项：经 netsh 配静态 IPv4（不填则自己跑 netsh） |

与 Linux 版的行为差异：

- **无挑战应答**：暂不支持 `--privatekey`/挑战应答，连 `--pubkey` 的 server
  会在认证一步被拒（Linux 端 TCP 认证见"TCP 挑战认证"）。
- **适配器持久**：tap-windows6 适配器不随进程退出删除，退出时只把 media
  status 置为"网线拔出"（干净下线）；`--mac/--mtu` 是注册表持久值。
- **无混杂**：Windows 协议栈不会把镜像来的"发往第三方 MAC 的单播帧"送进
  本机协议栈——顶替 IP 请用 `--mac` 克隆 server 网卡 MAC（对应
  [docs/single-ip-takeover.md](docs/single-ip-takeover.md) 的接管模式）；
  要嗅探全部镜像帧需 Npcap 之类抓包驱动绑定该适配器。
- 外层 UDP 分片在 Windows 上默认允许（等效 `IP_PMTUDISC_DONT`），无需设置。

## 设计要点

- **线程模型（全程阻塞，零轮询）**：所有泵线程都睡在 syscall 里，数据到达由内核唤醒，
  空闲时 CPU 占用为零——没有任何"试探循环"：
  - *client*：rx 线程（transport→tap，阻塞在 recv）、tx 线程（tap→transport，阻塞在
    read）、keepalive 线程（nanosleep 定时器，单次 syscall 发送）。main 只管生命周期：
    阻塞在读事件管道上，某线程死亡或信号到来才醒来做拆链/重连。
  - *server*：rx 线程（transport→注入网卡）、main 本身即镜像泵（阻塞 recvfrom 抓包
    socket；1s 接收超时是唯一的空闲 tick，用于在网卡安静时察觉断连/退出）；TCP 模式
    main 阻塞在 accept。
  - **无锁**：每条消息只一次发送 syscall（UDP sendto 原子；TCP 用 sendmsg 把长度头+
    载荷放进一个 iovec 一次发出，内核 socket 锁天然串行化并发写者），共享状态全是
    原子字（对端地址打包成一个 `u64`、死亡标志）。
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
- **TCP 模式（`--tcp`）**：同一帧格式改走 TCP 流（`u16` 长度前缀成帧），把拥塞控制、
  重传、 pacing 全部交给内核——算法由 sysctl 决定（如
  `net.ipv4.tcp_congestion_control=bbr`），代码不碰 cc，只设 `TCP_NODELAY` 与
  30s 发送超时。代价是队头阻塞（丢一个包整条流停顿），适合有损/拥塞路径，
  UDP 模式仍是无损局域网首选。连接断开即重连（server 重新 accept，client 3s
  重试），keepalive 保留作活性探测；代码里 UDP 与 TCP 是**两条独立核心循环**，
  逐帧热路径没有任何"哪种传输"的分支。
- **同 netns 部署要 `arp_ignore=1`**：server 网卡和 client tap 若在**同一个**
  netns/主机且同网段（如 testbed、同机 loopback 用法），默认 `arp_ignore=0` 会让内核
  用 server 网卡的 MAC 代答 tap IP 的 ARP——不需要隧道就能答。平时无碍（tap 经隧道的
  正确应答后到、覆盖），但 **TCP 断线期间只有 flux 代答**，对端邻居表被污染成 server
  网卡 MAC，重连后回包对 tap 是 `PACKET_OTHERHOST` 而被静默丢弃且无法自愈。同 netns
  跑就 `sysctl net.ipv4.conf.all.arp_ignore=1`；server 与 tap 分属不同 netns（如
  wifi.sh 拓扑）则天然免疫。
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
    和协议栈都会静默丢弃），必须在**流量源**`ethtool -K <if> tx off` 根除
    （testbed.sh / bench.sh 已内置）。
  - *tso/gso/gro*：GRO 在抓包点之前把帧合并成 64KB 超级帧——那不是线上的帧，
    且超过 UDP 单包上限 65507，TCP 过隧道会全灭。server 启动时自动关闭网卡的
    tso/gso/gro，**退出时恢复原值**（`--keep-offloads` 可保留不碰）。
- **MTU**：内层以太网帧 1514B + 外层 UDP/IP/以太网头 ≈ 1556B，超过 1500 时外层 IP
  自动分片（已设 `IP_PMTUDISC_DONT`）。对延迟敏感可在底层网络放大 MTU，或给 tap 设
  较小 MTU（如 1400）避免分片。
- **安全警告**：默认无认证、无加密，任何知道 server 端口的人都能注入帧/收到镜像
  流量，只可在可信网络使用；`--tcp --pubkey` 可加 client 身份认证（见"TCP 挑战
  认证"），但数据面仍不加密——需要机密性时套 WireGuard/IPsec 等（缓解措施见开头
  "法律声明与注意事项"）。

## 测试

```bash
make check                      # 认证模块自测（无需 root）：密钥解析、签名/验签、
                                 # socketpair 握手演练、防重放、与 openssl CLI 互操作
sudo bash test/testbed.sh        # veth 实验室：8 项断言
sudo bash test/auth.sh           # 挑战认证端到端：5 项断言（需 python3）
sudo bash test/wifi.sh           # 真实 WiFi 网卡 + netns 纯 L2 联网：5 项断言
sudo bash test/wifi-multiip.sh   # 真实 WiFi 多 IP：host 留 .101，client 接管 .123：5 项断言
sudo bash test/bench.sh          # 吞吐/延迟测速（TRANSPORT=tcp 测 --tcp）
```

### testbed.sh（veth 实验室，无 bridge）

在两个 network namespace 间搭一对 veth，server 直接接管 veth 网卡，断言：
① tap↔对端双向 ping（ARP+ICMP 全走隧道）；② 发往无关 MAC 的单播帧被镜像到 tap
（混杂）；③ 线上 echo request/reply 恰好 3/3（无环路无风暴）；④ client 换端口重连后
server 重新学习对端（NAT 漫游）；⑤ `--bind 127.0.0.1` 时 socket 实际只听环回、本机
client 仍通；⑥ `--tcp` 传输：TCP 连接建立、ARP+ICMP 经成帧流过隧道（顺带打印内核
实际使用的拥塞控制算法）；⑦ **TCP 断线重连**：杀掉 server 模拟断线，断言期间 tap
始终 UP/IP 不丢、流量只丢包、client 不退出，server 回来后自动重连恢复；⑧
`--filter-ip` 多 IP 过滤：被过滤 IP 经隧道可达（ARP 透传由 client 应答）、网卡其余
IP 仍由本机协议栈应答、且这些流量一帧都不出现在 tap 上。日志在
`/tmp/a2tp-srv.log`、`/tmp/a2tp-cli.log`。

### auth.sh（挑战认证端到端）

同 testbed 的 veth 拓扑，server 以 `--tcp --pubkey` 启动，断言：A1 正确密钥被
挑战、认证（日志显示第几把钥匙）且隧道通；A2 错误密钥每次重试都被拒、连接始终
建立不起来、client 不退出持续重试；A3 无密钥 client 同样被拒；A4 无 `--pubkey`
的 server 遇上带密钥 client——等不到挑战则照常无认证建隧道；A5 **重放攻击**：
用授权私钥（openssl CLI 预签名）对一个时间戳落后 120 秒的过期挑战做合法签名
发给 server，仍被拒绝且连接被断。日志在 `/tmp/a2tp-auth-e2e/`。

### wifi-multiip.sh（物理网卡多 IP 实战：一个 IP 搬给远端）

server 接管物理 WiFi 网卡并用 `--filter-ip` 只镜像被接管的 IP（该 IP 先从 host 协议
栈删除，脚本退出自动还原；若 IP 本不在 host 上则探测空闲后直接使用）。client 住在
netns 里，tap 克隆 WiFi 网卡 MAC 并占用被接管的 IP。断言：M1 host 自己的 IP
（192.168.1.101）照常上互联网；M2 被接管 IP（192.168.1.123）经隧道上互联网
（ARP 透传 + 过滤镜像）；M3/M4 DNS 与 HTTP 200；M5 host 的流量一帧都不泄漏到 tap。
用法：`sudo bash test/wifi-multiip.sh [iface] [ip]`。

### wifi.sh（物理网卡实战：netns 纯 L2 联网）

server 在 root netns 接管**物理 WiFi 网卡**（默认 `wlp8s0`）；client 与 tap 住在
netns `l2t-wifi` 里，tap 克隆 WiFi 网卡的 MAC（802.11 managed 模式只交付发给自己
MAC 的单播，克隆 MAC 才能收到网关回包），占用 WiFi 子网中的一个空闲 IP。隧道的
UDP 走一对专用 veth 底座（MTU 2000，内外分离），其余一切字节都通过克隆链路出现在
**真实 WiFi LAN** 上：

```
root ns:  a2tp-srv -i wlp8s0 ◄─ UDP 底座(veth) ─► a2tp-cli (netns) ─ wifi0(tap)
                └── 真实 WiFi L2 透传：ARP/DNS/ICMP/HTTP ──► 路由器 ──► 互联网
```

断言：W1 server 学到对端；W2 netns→真实网关 ping；W3 netns→公网 223.5.5.5；
W4 DNS；W5 HTTP 200。脚本自动处理两个环境坑：底座 veth 两侧 `ethtool -K tx off`
（veth 校验和伪影），以及把底座接口临时加入 firewalld trusted zone（默认 zone 丢弃
入站 UDP 但放行 ping，只改运行时配置、退出还原）。

### bench.sh（测速）

基线直连 veth 对照，随后经隧道：ping 延迟、TCP 双向（tap→LAN 注入路径 / -R 镜像
路径）、UDP 1370B 定速、64B 小包 pps、tap MTU 1500 时的外层分片代价（仅 UDP 模式，
TCP 传输按 MSS 分段不 IP 分片）。iperf3 服务端全程常驻避免端口竞争。
`TRANSPORT=tcp bash test/bench.sh` 测 `--tcp` 模式，`T=<秒>` 调每个 iperf 时长。

## 扩展方向

- 多 client：server 端 peer 表 + session id 区分（当前单 client）
- 序列号/重排（内核 `send_seq`/`recv_seq` 的思路）
- `--mirror-tx`：把本机发出的帧也镜像出去（需对注入帧做去重）
- 内核 L2TP 互通：把头部换成 `SessionID+Cookie` 即可与 `ip l2tp add` 对接
