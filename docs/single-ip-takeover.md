# 单 IP 接管指南（多 IP 网卡搬移一个 IP 给远端）

网卡上有多个 IP 时，可以把**其中一个**搬给远端机器使用：从本机协议栈删除该 IP，
`a2tp-srv` 只把它对应的流量镜像过隧道，其余 IP 的流量完全不受影响。本机与远端
**同时在线、各用各的 IP**。

```
                server 主机 (网卡多 IP)                        client 主机
        ┌───────────────────────────────────┐          ┌──────────────────────┐
LAN ────┤ eth0 / wlp8s0                     │          │  tap a2tp0           │
        │   192.168.1.101  ← 保留，host 自用 │   隧道    │   192.168.1.123/24   │
        │   192.168.1.123  ← ip addr del    │ ───────► │   (接管过来的 IP)     │
        │        ▲                          │  UDP/TCP │                      │
        │        │ a2tp-srv --filter-ip .123│          │  a2tp-cli            │
        └────────┼──────────────────────────┘          └──────────┬───────────┘
                 │ 只镜像 dst=.123 的帧                            │
                 │ 其余帧协议栈照常处理（旁路，零干扰）              │
```

本文以 `192.168.1.101`（保留）/ `192.168.1.123`（搬走）/ 网关 `192.168.1.1` 为例。
全程有自动化测试背书：`testbed.sh` 的 T8（veth 实验室）与 `wifi-multiip.sh`
（真实 WiFi，5 项断言）。

---

## 1. 工作原理

`a2tp-srv` 用 AF_PACKET 混杂模式**旁路**抓包——它看得到每个帧，但从不拦截，
协议栈对每个帧的处理与没有 a2tp 时完全一样。"过滤"只决定**镜像哪些帧**：

| 网卡收到的帧 | 行为 |
|---|---|
| IPv4，目的地址 ∈ `--filter-ip` 集合 | 镜像过隧道 → client 写入 tap |
| IPv4，目的地址 ∉ 集合（如 host 自己的 .101） | **不镜像**，协议栈照常处理（host 自己应答） |
| ARP（request/reply，任何 IP） | **全部透传镜像**——client 协议栈需要 |
| 其他 ethertype（如纯 IPv6） | 不镜像，留在本机 |

client 方向（tap → 隧道 → server）**不过滤**，client 发出的每个帧都原样注入网卡。

### ARP：server 零状态，client 协议栈自己应答

这是本设计的关键决策（讨论过 server 端代答，最终放弃）：

- 路由器广播 `who-has 192.168.1.123` → server 透传给 client → **client 的 tap
  协议栈应答** `is-at <tap MAC>` → 注入回网卡 → 路由器学到表项
- 所有权**不相交**：host 内核应答它还持有的 IP（.101），client 应答它独占的 IP
  （.123，host 上已 `ip addr del`）——**没有任何两个应答者**，无竞争、无 ARP flux
- client 离线期间该 IP 无人应答 → 不可达（语义如实：IP 的主人不在）；client 回来后
  路由器对 STALE 表项的 unicast 探测经隧道到达 client，应答后自愈
- server 不需要理解 ARP、不维护任何邻居状态，断了、重启了都不影响语义

如果由 server 代答（用网卡 MAC），client 在线时会出现两个应答者；且 client 离线时
server 继续宣称 IP 在线、流量却只能丢弃——"诚实失败"优于"黑洞"。

### 注入路径

client 发出的帧（TCP 响应、它自己的 ARP request）经隧道到 server，从同一个
AF_PACKET socket 原样注入网卡，源 MAC 是 tap 的 MAC。

- **有线网卡**：任何 tap MAC 都行——混杂模式能抓到发往任意 MAC 的单播
- **WiFi 网卡（managed 模式）**：tap **必须克隆网卡 MAC**——AP 只向 station MAC
  交付单播，且注入帧的源 MAC 必须是 station MAC，否则 AP 丢弃

---

## 2. 前提与约束

1. **被接管的 IP 必须从 host 协议栈删除**（`ip addr del`）。留着会导致 host 内核
   也应答它的 ARP、也消费它的包——双主人。
2. underlay（隧道本身的 UDP/TCP）不能依赖被接管的 IP。同机实验用 `--bind
   127.0.0.1`；跨机用网卡上**保留的** IP 或另一张网卡的 IP。
3. `--filter-ip` 按 **IPv4 目的地址**匹配；IPv6 流量不在接管范围内（会被留在本机）。
4. server 端 root/CAP_NET_RAW，client 端 root/CAP_NET_ADMIN。
5. 无认证无加密，仅限可信网络（需要安全在外面套 WireGuard 等）。
6. 同 netns 特例：若 server 网卡与 client tap 在**同一个** netns 且同网段（如同机
   loopback 部署），该 netns 需 `sysctl net.ipv4.conf.all.arp_ignore=1`，原因见
   README 设计要点"同 netns 部署"。

---

## 3. 操作步骤

### server 端

```bash
# 1) 把 IP 从协议栈拿掉（先记下来，还原要用）
sudo ip addr del 192.168.1.123/24 dev wlp8s0

# 2) 起服务：只镜像这个 IP（可多个：--filter-ip a,b 或重复多次）
#    WiFi 网卡建议同时记录 MAC，client 要克隆：
cat /sys/class/net/wlp8s0/address

sudo ./a2tp-srv -i wlp8s0 --filter-ip 192.168.1.123
#   跨机时若网卡多 IP，建议 --bind <保留IP> 精确指定 underlay 监听地址
#   需要内核重传/拥塞控制则双方加 --tcp
```

### client 端

```bash
# WiFi：必须克隆 server 网卡 MAC；有线可省略 --mac
sudo ./a2tp-cli -s <server_ip> --tap a2tp0 \
     --mac 04:68:74:37:9a:4f

# 地址路由不归 client 管，手工配：
sudo ip addr add 192.168.1.123/24 dev a2tp0
sudo ip route add default via 192.168.1.1 dev a2tp0
# 建议打开：地址生效时发 gratuitous ARP，立刻向 LAN 宣告
sudo sysctl -w net.ipv4.conf.all.arp_notify=1
```

---

## 4. 验证

```bash
# client 侧：接管 IP 应能出网（ARP 透传 + 过滤镜像两条路径都验到）
ping -I a2tp0 -c3 192.168.1.1        # 网关（ARP 全走隧道）
ping -I a2tp0 -c3 223.5.5.5          # 公网（路由器路由）
getent hosts www.baidu.com            # DNS
curl -s -o /dev/null -w '%{http_code}\n' http://www.baidu.com   # 期望 200

# server 侧：host 自己的 IP 不受任何影响
ping -I wlp8s0 -c3 223.5.5.5

# 隔离性（可选）：host 流量不得出现在 client tap 上
sudo tcpdump -ni a2tp0 -c 8 'ip and host 192.168.1.101'   # 应 0 packets
```

server 日志确认过滤生效（`/tmp` 或终端）：

```
mirror filter: ipv4 dst in {192.168.1.123} (arp passes, rest stays local)
```

---

## 5. 故障排查

| 症状 | 原因 → 处置 |
|---|---|
| client ping 网关不通，tap 上看不到 ARP request | underlay 断了：查 server `peer:` 日志、防火墙放行 UDP 1702（firewalld 默认 zone 丢入站 UDP，见 `wifi.sh` 的 trusted-zone 处理） |
| ARP 有来有回但 ping 不通 | IP 没从 host 删除 → host 内核把 request/echo 也消费了；`ip addr` 确认 |
| WiFi 上完全不通 | tap 没克隆网卡 MAC → AP 不交付/丢弃注入帧；`--mac $(cat /sys/class/net/wlp8s0/address)` |
| 通一下就断/时好时坏 | 同 netns 部署缺 `arp_ignore=1`（ARP flux 污染对端邻居表，见 README） |
| 大流量全丢 | 网卡 offload：server 启动会自动关 tso/gso/gro（日志有记载）；流量源侧 veth 实验另需 `ethtool -K <if> tx off` |
| client 换网后失联 | UDP 模式自动 NAT 漫游（每包重学对端）；TCP 模式 3 秒重连——等一个退避周期 |
| server 主机自己断网 | 与本功能无关的方向性问题：`--filter-ip` 不过滤的帧协议栈照常处理；先查 host 自身路由/ DHCP |

---

## 6. 还原

```bash
# client 停掉（tap 随进程消失）
sudo pkill a2tp-cli

# server 停掉（自动恢复网卡 tso/gso/gro）
sudo pkill a2tp-srv

# IP 放回协议栈
sudo ip addr add 192.168.1.123/24 dev wlp8s0
# 立刻刷新邻居（可选）：向 LAN 重新宣告
sudo arping -U -I wlp8s0 -c 3 192.168.1.123
```

`test/wifi-multiip.sh` 把上述整套（删除→接管→验证→还原）做成了 5 项断言的自动
化测试，可直接当参考实现或回归用：

```bash
sudo bash test/wifi-multiip.sh [iface] [ip]     # 默认 wlp8s0 192.168.1.123
```
