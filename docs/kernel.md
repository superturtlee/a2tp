# a2tp 内核数据面（a2tp.ko + a2tpctl）

> 法律声明与安全警告同 [README](../README.md) 开头：无认证无加密，限可信网络或
> 叠加 WireGuard/IPsec 使用；**不得用于非法跨境通信**。

用户态版（`a2tp-srv`/`a2tp-cli`）每帧 2 次 syscall + 2 次用户态拷贝；内核版把
整个数据面下沉进一个可卸载内核模块，数据面全程不出内核。**线格式完全一致**
（UDP 1702，`type(1B)+以太网帧`），内核版与用户态版可任意交叉对接
（k-srv ↔ u-cli、u-srv ↔ k-cli）。

```
        server 主机 (HK)                              client 主机 (家)
┌──────────────────────────────────┐        ┌─────────────────────────────┐
│ eth0 ◄─ rx_handler (每帧旁路)     │        │ a2tp0 (rtnl_link netdev)    │
│   │镜像                              UDP   │   ▲ ndo_start_xmit          │
│   │  skb_clone + type 字节 ═══════════════╪═══│ encap 回调               │
│   ▼注入                              :1702 │   dev_forward_skb          │
│  (dev_queue_xmit) ◄──────────────────────────┘                            │
└──────────────────────────────────┘        └─────────────────────────────┘
        外层 UDP 走完整内核路由栈 ──► 策略路由可把隧道引进 wg0/IPsec，透明叠加
```

**为什么是 LKM 而非 XDP**：XDP redirect 绕过协议栈，外层 UDP 无法走策略路由进
WireGuard——与"隧道套 WireGuard/IPsec"的结构性需求冲突。内核版外层走完整路由
路径（`ip_route_output_key` / `ipv6_dst_lookup_flow`，逐包查路由、xfrm 感知），
叠加是免费的。

## 编译与加载

```bash
make kmod          # 产出 kernel/a2tp.ko（需要内核 headers：/lib/modules/$(uname -r)/build）
make a2tpctl       # 用户态控制工具（零依赖，裸 netlink 构消息）

sudo modprobe udp_tunnel          # v4 socket/xmit 符号所在模块
sudo modprobe ip6_udp_tunnel      # v6 符号（udp_sock_create6 等）在独立模块
sudo insmod kernel/a2tp.ko
```

`udp_tunnel` 与 `ip6_udp_tunnel` 是硬依赖（v6 符号在 net/ipv6/ip6_udp_tunnel.ko，
不是 udp_tunnel.ko 的一部分）；`wireguard` 仅在用它做承载时需要。

## 快速上手

```bash
# server：接管 eth0（镜像+注入，自动开混杂、关 tso/gso/gro，退出/del 恢复）
sudo ./a2tpctl srv add -i eth0

# client：本地出现 a2tp0 网卡（地址路由照常用 ip(8) 配）
sudo ./a2tpctl cli add a2tp0 remote <server_ip>
sudo ip link set a2tp0 up
sudo ip addr add 192.168.1.123/24 dev a2tp0
```

实例生命周期：只有 `srv del` / `cli del`（或所属 netns、被接管网卡本身消失）会
销毁实例。**承载断不会拆实例**（见"可靠性契约"）。

## a2tpctl 参考

```
srv add -i <iface> [-p <port>] [-b <carrier ip>]
        [--peer <ip:port>] [--peer-timeout <sec>]
        [--filter-ip <a[/m][,a[/m]..]>] [--filter-ip6 <a[/m]..>]
        [--no-self-filter] [--keep-offloads]
srv del -i <iface>
srv status                       # 任意用户可读（同 `ip link`）
cli add <name> remote <ip[:port]> [local <carrier ip>]
        [local-port <n>] [keepalive-ms <n>] [mtu <n>] [mac <aa:..>]
cli del <name>
```

| flag | 说明 |
|---|---|
| `-p <port>` | UDP 端口，默认 1702 |
| `-b <ip>` | server 侧 pin 承载地址（socket 只收/只发该源）。不 pin = 双栈 wildcard |
| `--peer <ip:port>` | 锁定唯一合法对端，其余源注入计数丢弃（`peer_pinned_drop`） |
| `--peer-timeout <s>` | 对端静默 N 秒暂停镜像待重学（默认 30，0=永不） |
| `--filter-ip/-ip6` | 多 IP 网卡模式：只镜像目的地址命中的帧（掩码支持前缀长度 `10.0.0.0/24` 或地址式 `255.255.255.0`，两族独立）。ARP/NDP 恒透传 |
| `--no-self-filter` | 关闭隧道自身 UDP 五元组过滤（防隧道套隧道回声，默认开） |
| `--keep-offloads` | 不动网卡 offload（默认自动关 tso/gso/gro，del/退出恢复） |
| `local <ip>` | client 侧 pin 承载源地址（族须与 remote 一致） |
| `local-port <n>` | client 源端口，`0`=随机（同机/server 同 netns 时必须 0） |
| `keepalive-ms <n>` | 默认 10000，`0`=关；启动即发首包让 server 学到对端 |

### `srv status` 输出解读

```
srv eth0: local *:1702  peer learned 1.2.3.4:52424 (age 12ms)  timeout 30000ms
    mirror=19 inject=11 tx_err=0 rx_data=0 rx_ka=2 rx_bad=0 pass_filter=0 ...
```

| 计数 | 含义 |
|---|---|
| `mirror` | 已镜像给 client 的帧 |
| `inject` | 收到并注入网卡的 client 帧（server 不增 `rx_data`，那是 client 侧统计） |
| `tx_err` | 镜像/发送因路由或承载失败被计数的帧（承载断期间的量度） |
| `rx_ka` | 收到的 keepalive |
| `rx_bad` | 坏包（错 type、太短等） |
| `pass_filter` / `pass_self` / `pass_no_peer` / `pass_gso` / `pass_mtU` | 各放行路径：过滤不命中 / 隧道自身流量 / 尚无对端 / GSO 超帧 / 超长帧 |
| `peer_pinned_drop` | `--peer` 锁定下的陌生源注入尝试 |

client 侧统计看 netdev 计数器：`ip -s link show a2tp0`。

### 与 ip(8) 的关系

`ip link add x type a2tp remote ...` **不被 iproute2 支持**——`remote` 等是我们
的私有 `IFLA_INFO_DATA` 属性，iproute2 没有内置 a2tp 解析器（会报 "Garbage
instead of arguments"）。创建必须用 `a2tpctl cli add`；`ip -d link show` 能看到
全部属性（`fill_info` 已实现）；`ip link set/del/addr/route` 等标准操作照常。
这与 wireguard kind 必须用 `wg(8)` 是同一模式。

## IPv6

```bash
# v6 传输：remote 用 v6 地址即可（带端口要括号）
sudo ./a2tpctl cli add a2tp0 remote '[fd00::1]:1702'
# server 不 pin 时开双栈 wildcard（v4+v6 两个 socket），任一族可达
sudo ./a2tpctl srv add -i eth0
# v6 掩码过滤（NDP 恒透传，无需担心邻居发现被滤掉）
sudo ./a2tpctl srv add -i eth0 --filter-ip6 'fd00::2/127,fd00::9/64'
```

内外族独立：外层 v6 内层 v4（或反之）都正常工作（testbed T7 即外 v6 内 v6）。

## 可靠性契约（内核版的核心语义）

1. **逐包路由，零缓存 dst**：每个外层 UDP datagram 独立查路由（不 connect、
   不缓存），策略路由/wg/ipsec 的变化下一包立即生效。
2. **承载/路由丢失 = 丢这一帧并计数（`tx_err`），实例永不拆**：
   - client **不指定 `local`**（默认）：源地址逐包由路由表定。WiFi 断开换网线
     （默认路由跳变、源 IP 整个换掉）→ 隧道零配置自愈，server 从下一包重学对端
     （同 socket 同源端口，仅地址变——testbed T10）。
   - server `-b <ip>` / client `local <ip>`（pin）：pin 的地址消失 → 该方向路由
     查找必败，帧被计数静默丢弃，实例存活等地址回来（testbed T9 / wg W3、W4）。
3. **NAT 漫游**：双方从每个收包的源地址刷新对端；client keepalive 维持 NAT 映射，
   换出口后 server 自动跟到新端点。
4. **实例销毁只有三条路**：`srv del`/`cli del`、所属 netns 删除、被接管网卡
   unregister。其余任何网络变化都不拆。

## 权限模型

检查全部由 netlink 核心执行，语义是"**目标 netns 归属的 user namespace 内的
CAP_NET_ADMIN**"：

- genl（srv add/del）：`GENL_UNS_ADMIN_PERM` → `netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN)`
- rtnl（client netdev）：rtnetlink 核心 `netlink_net_capable(skb, CAP_NET_ADMIN)`
- `srv status` 故意全员可读（同 `ip link`）

实测矩阵（test/caps.sh，全过）：

| 场景 | 结果 |
|---|---|
| 普通用户（无 cap，初始 netns） | 拒 EPERM（status 可读） |
| 真 root | 放行 |
| root 剥掉 CAP_NET_ADMIN | 拒 EPERM |
| userns 假 root（`unshare -Ur`）操作初始 netns | 拒 EPERM（cap 不覆盖 init_user_ns） |
| userns 假 root 自建 netns（`unshare -Urn`） | 放行（netns 归其 userns 所有） |

容器部署姿势：给容器 `CAP_NET_ADMIN` + 自有 netns 即可完整运行 server/client
（rx_handler、netdev、genl/rtnl 都在 netns 内工作）。

## 叠加 WireGuard / IPsec

外层 UDP 就是普通内核 UDP，策略路由引到 wg0/xfrm 即成加密承载，a2tp 无感知：

```bash
# wg：client remote 直接填 server 的 wg overlay 地址
sudo ./a2tpctl cli add a2tp0 remote 10.99.0.1    # 外层自然路由进 wg0
```

- 验证：`test/qemu.sh wg` 断言底层抓包只见 wg 密文、无明文 udp/1702（W1b），
  及三种承载断连的自愈（W2-W4）。
- IPsec 同理：`test/qemu.sh xfrm` 断言底层只见 ESP（X1）。
- 注意 Ubuntu 24.04+ 给 wg(8) 配了 AppArmor profile（`/etc/apparmor.d/wg`），
  私钥文件只允许放 `/etc/wireguard/` 下——放别处 `wg set private-key` 对 root
  也报 `fopen: Permission denied`。

## 部署约束

- **rx_handler 每设备仅一个**：被接管的网卡不能同时做 bridge/macvlan 的下级
  （与它们互斥，内核接口如此）。HK 云机 eth0 无冲突；目标网卡已被占则评估换口。
- 接管时自动：开混杂（镜像发往其他 MAC 的单播）、关 tso/gso/gro（防 GRO 超帧
  超 UDP 上限）；`srv del`/模块卸载/网卡消失时全部还原。
- server 与 client tap 同 netns 且同网段时需要 `arp_ignore=1`（详见 README
  设计要点，语义与用户态版相同）。
- netns 完整支持：`ip netns exec <ns> ./a2tpctl ...`，netns 删除自动清理其实例。

## 实现细节备忘（踩过的坑）

- **镜像帧必须 `skb_scrub_packet()`**：混杂捕获的帧按内层目的 MAC 被网卡分类，
  发往 client 接管地址的是 `PACKET_OTHERHOST`；v4 的 `iptunnel_xmit()` 免费帮你
  scrub，v6 的 `ip6tunnel_xmit()` 不 scrub，`ip6_rcv_core` 会把 OTHERHOST 直接
  丢弃——v6 传输曾因此只通多播不通单播。mirror 路径统一 scrub（保留 mark，
  不伤策略路由）。
- 注入路径手工做 receive 侧清洗（`secpath_reset`/`nf_reset_ct`/`ip_summed`/
  `pkt_type=PACKET_HOST`/`mark=0`），等价 packet socket 的发送语义。
- client netdev 的 features 清掉 checksum/TSO/GSO 位，等价用户态 TAP 的
  `TUNSETOFFLOAD(0)`：协议栈软件算校验和、按 MTU 分段。

## 测试

内核模块测试**只在 QEMU 一次性 overlay VM 里跑**（`tools/qemu-vm.sh` 沙箱，
宿主机 insmod 曾打崩网络栈——纪律见仓库约定）：

```bash
./test/qemu.sh testbed   # T1-T10：镜像/注入/防环/漫游/多IP过滤/v6/承载断/路由跳变
./test/qemu.sh wg        # W1-W4：wg 加密承载 + 三种断连自愈
./test/qemu.sh xfrm      # X1-X3：IPsec 承载 + 明文对照
./test/qemu.sh caps      # C1-C5：CAP_NET_ADMIN × userns 权限矩阵
./test/qemu.sh sh '<cmd>' # 沙箱内任意命令
```

首次：`tools/qemu-vm.sh fetch && tools/qemu-vm.sh bake`（镜像含 wireguard-tools）。
VM 经 9p 挂载仓库到 `/mnt/a2tp`，优先加载宿主构建的 `kernel/a2tp.ko`，版本漂移
时自动在 VM 内 `make kmod` 重建。
