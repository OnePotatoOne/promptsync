# promptsync

在多台电脑之间**加密同步 prompt**（默认同步 Cindy 的 `system_prompt.md` / `SOUL.md`，也可配置任意 Markdown 目录）。

- **服务端（server）** 是唯一权威源：本地 prompt 一变，就重新计算 SHA-256 并递增 epoch。
- **客户端（agent）** 每 10 秒向服务端校验 hash；不一致就拉取整包，原子写入本地，记录日志。
- 传输走 **UDP**：先做**随机端口敲门**，敲门成功前数据端口根本不绑定；握手用 **X25519 + 预共享密钥认证**，数据用 **AES-256-GCM**，带防重放窗口。
- 连续 **2 分钟**失联自动通过**飞书自建应用**发离线告警（恢复后可选恢复通知）。
- 绑定后可以直接给机器人**私聊发纯文本**，服务端自动覆盖唯一那个 prompt 文件，agent 再自动同步。
- **编译期随机生成所有密钥/口令**，仓库里不存在任何固定密钥；需要多台机器互通时可用 `cluster_secret` 显式对齐。
- **个人配置集中在一个目录**（默认 `./config`，空目录启动时自动从模板生成，整个目录被 git 忽略）。
- 单文件 Rust 二进制，本地编译；GitHub Actions 交叉编译 x86_64 安装包。

> 这是「可信内网/自建服务器 + 自己的多台电脑」场景的工具，不是面向公网多租户的服务。安全边界见 [安全模型](#安全模型与边界)。

---

## 1. 快速开始

### 1.1 本地编译

```bash
cargo build --release
./target/release/promptsync --version
```

编译时 `build.rs` 会：

1. 生成 32 字节随机集群密钥（也可以由 `PROMPTSYNC_BUILD_SECRET` 或本地 `secrets/cluster_secret.hex` 指定）；
2. 打印本次构建指纹（例如 `promptsync build fingerprint 55cb64567da0`）。

飞书使用**自建应用**，`app_id`/`app_secret` 只保存在本机配置目录，**不会编进二进制**。

同一次 `cargo build` 产出的 server 和 agent 天然共享密钥；**不同次编译**的二进制默认互不信任，这是刻意设计。

### 1.2 个人配置目录（默认 `./config`）

所有个人配置都在**一个目录**里，默认是当前工作目录下的 `config/`：

```
config/
├── config.toml          # 唯一的配置文件（首次启动从模板生成）
├── state/               # 运行状态：agent-state.json / agents.json / managed.json / backups/
└── logs/                # 日志
```

规则：

- 目录**默认为空**（仓库里不存在、也不会提交）。第一次运行 `server` / `agent` / `status` 时如果里面没有 `config.toml`，会按 `templates/config.toml` 模板生成一份，权限 0600。
- 之后启动**绝不覆盖**已有配置；要重新生成用 `promptsync init --force`（旧文件会先备份成 `config.toml.bak.<时间戳>`）。
- 模板里的 `{home}`、`{cindy_root}`、`{config_dir}` 会在生成时替换成本机路径。
- `config/` 已在 `.gitignore` 中，**不会被上传到 GitHub**；CI 还会检查是否有跟踪文件落在 `config/` 下，发现即失败。
- 配置目录可以随便换（推荐服务方式运行时用绝对路径）：

```bash
promptsync --config-dir /srv/promptsync/config server
PROMPTSYNC_CONFIG_DIR=~/psync-config promptsync status
promptsync --config /etc/promptsync/config.toml status   # 直接指定文件（目录取父目录）
```

> 因为默认目录是**相对当前工作目录**的 `./config`，用 systemd/launchd 长驻时请设置 `WorkingDirectory` 或直接传 `--config-dir <绝对路径>`（`packaging/install.sh` 会自动处理好）。

### 1.2.1 启动交互（server / agent）

`server` 和 `agent` 在**终端里**启动时会先做一次确认，避免拿错配置直接跑：

- **首次启动**（配置文件刚由模板生成）：
  - 打印配置目录、状态目录、日志目录；
  - 列出关键项并给出指引：agent 的 `agent.server` / `agent.port`、`cluster_secret`、`feishu.app`、`sync.sources`（服务端则是 `server.bind` / `server.port` 等）；
  - 菜单：`1` 直接启动 / `2` 交互式修改关键项 / `3` 用 `$EDITOR` 打开配置文件。
  - agent 首次启动且 `agent.server` 还是 `127.0.0.1` 时，默认选中 `2`，引导你先把服务端地址填好。
- **后续启动**（已有配置）：
  - 先问「是否使用已有配置启动？[Y/n]」，**默认是**；
  - 选 `n` 后进入同样的菜单：交互式修改关键项（server 地址/端口）、或直接用编辑器修改；
  - 修改写回后会重新校验，校验失败会提示继续修改或退出。
- **不会打扰脚本和服务**：以下情况自动跳过所有提问
  - 非终端环境（stdin/stdout 不是 TTY，例如 systemd、launchd、cron、管道）；
  - 传了 `--non-interactive`；
  - 已经用命令行参数覆盖了配置（`--server` / `--port` / `--bind` / `--once`）。

```bash
promptsync --non-interactive agent --config-dir /srv/promptsync/config
```

交互式修改会**保留配置文件里的注释**（只改对应的一行）；修改前也可以随时手动编辑 `config/config.toml`。

### 1.3 启动服务端

任选一台长期在线的电脑（建议小主机/NAS）：

```bash
cd ~/workspace/promptSync
./target/release/promptsync server
```

首次运行会创建 `config/config.toml`，并在终端里显示配置指引与确认菜单（见 [1.2.1](#121-启动交互server--agent)）。如果配置里启用了飞书，还会进入一次性的扫码绑定流程（见第 5 节）。日志会显示数据端口与敲门端口池（默认 12 个）；每次敲门随机选 3–6 个端口、随机顺序、随机间隔。数据端口**只有在敲门成功后才会被绑定**，扫描器看到的是「关闭」状态。

### 1.4 启动 agent

在每台需要同步的电脑上，把 `config/config.toml` 里的 `agent.server` 改成分机地址：

```bash
# 先手动跑一次看结果（带 --server/--once 时不提问）
./target/release/promptsync agent --server 192.168.1.10 --once

# 前台常驻（首次会给出配置指引并要求确认）
./target/release/promptsync agent
```

长期运行用 `systemd --user` / `launchd`，见 [第 8 节](#8-开机自启动)。

### 1.5 多台机器密钥对齐

三种方式任选：

1. **分发同一个二进制**（最省事）：所有机器用同一份 `cargo build` 产物。
2. **显式设置集群密钥**：
   ```bash
   # 服务端
   promptsync secret --show        # 打印 64 位 hex（注意保密）
   # agent 端（会写进该机器的 config/config.toml，保留模板注释）
   promptsync secret --set <hex>
   ```
3. **自己生成密钥**（推荐用于公网发布版）：
   ```bash
   promptsync secret --generate    # 打印一个新的随机密钥
   promptsync secret --set <hex>   # 服务端和所有 agent 都设置同一个值
   ```

只要 `cluster_secret` 相同，端口池、敲门标签密钥、握手密钥都会自动一致；无需手工对齐端口。敲门的具体端口/顺序每次都随机，不依赖任何固定序列。

---

## 2. 同步哪些 prompt

`config/config.toml` 的 `[[sync.sources]]` 决定同步内容。默认（由模板生成）：

| id | 根目录 | 匹配 |
|---|---|---|
| `cindy-bots` | macOS: `~/Library/Application Support/CindyGlobal/owners`；Linux: `~/.config/CindyGlobal/owners`；Windows: `%APPDATA%\CindyGlobal\owners` | `*/bots/*/system_prompt.md`, `*/bots/*/SOUL.md` |
| `pi-prompts` | `~/.pi/agent/prompts` | `**/*.md`（Pi 的 prompt 模板） |
| `cindy-prompts` | `~/.cindy/prompts` | `**/*.md` |
| `shared` | `~/.promptsync/shared` | `**/*.md`（放任意想同步的 prompt） |

bundle 里的路径是 **`<source id>/<相对路径>`**。所以不同机器即使家目录不同，只要 source id 一致，就能一一对应落盘。服务端多出来的 source（agent 没配置）会被 agent 忽略并写一条 warn 日志，不会来回重复拉取。

自定义示例：

```toml
[[sync.sources]]
id = "cindy-bots"
root = "~/Library/Application Support/CindyGlobal/owners"
globs = ["*/bots/*/system_prompt.md", "*/bots/*/SOUL.md"]

[[sync.sources]]
id = "team-prompts"
root = "~/Workspace/prompts"
globs = ["**/*.md", "**/*.txt"]
```

规则：

- glob 支持 `*`、`?`、`**`；路径分隔符统一为 `/`；
- 默认跳过符号链接（`sync.follow_symlinks = true` 可打开）、隐藏目录、`.DS_Store`、`*.psync.tmp`；
- 单文件上限 512 KiB，整包上限 `sync.max_bundle_bytes`（默认 1 MiB），文件数上限 1024；
- 服务端是权威：agent 本地手工改过的 prompt 会在下一次拉取时被覆盖（覆盖前自动备份，见第 7 节）。

---

## 3. 工作流程

```
agent                         server
  │  1. knock × 随机 N (UDP) ────▶  校验 HMAC 标签 + 时间窗 + 端口/slot 绑定
  │      随机子集/顺序/间隔          ✓ 打开该 IP 的 gate（TTL 90s）
  │                                ✓ 此刻才 bind 数据端口
  │  2. HELLO (X25519)   ───────▶  校验 MAC，回 READY
  │  ◀──────────── READY
  │  3. STATUS            ───────▶  返回 epoch + SHA-256
  │  ◀──────────── STATUS
  │      hash 相同 → BYE，本轮结束
  │  4. BUNDLE            ───────▶  返回全量文件（分片+ACK+重传）
  │  ◀──────────── BUNDLE
  │     校验 hash → 原子写入 → 备份 → 日志 → BYE
  │                                gate 过期、无会话 → 关闭数据端口
```

- 轮询间隔 `agent.poll_secs`（默认 10s）。
- 只同步 hash 变化；服务端每 2s 扫描一次源目录，变更即换 hash。
- 全部报文为加密记录：`magic|version|type|session|msg_id|frag|frag_cnt|counter|AEAD(payload)`。
  AAD 覆盖头部，`counter` 单调递增并有 1024 位滑动窗口防重放。
- 大消息按 1080 字节分片，接收端用 bitmap ACK，发送端只重传缺失分片（RTO 250ms 起，指数退避到 1.5s）。

协议实现见 `src/crypto.rs`、`src/wire.rs`、`src/server.rs`、`src/agent.rs`。

---

## 4. 安全模型与边界

### 4.1 做了什么

- **密钥不落地仓库**：`build.rs` 每次编译生成新的 32 字节随机密钥；也可从环境变量/本地 `secrets/`（git 忽略）注入。仓库中没有任何固定口令或端口。
- **个人配置不进仓库**：默认配置目录 `./config` 整体被 `.gitignore` 忽略；CI 守卫会拒绝任何 `secrets/`、`config/`、`*.pem`、`*.key`、`.env` 等被跟踪。
- **握手**：临时 X25519（前向保密）+ 用集群密钥对完整报文做 HMAC-SHA256（双向认证、防中间人、防时钟外重放 ±600s）。
- **会话密钥**：HKDF-SHA256 从 ECDH 共享密钥 + 双方 nonce 派生，上下行各一把 AES-256-GCM 密钥。
- **记录层**：每个报文独立 nonce（方向前缀 + 单调计数），1024 位重放窗口；篡改即认证失败、静默丢弃。
- **端口敲门（随机化）**：集群密钥推导出 12 个端口的池；每次尝试由 agent 随机选 3–6 个、随机顺序、随机延迟（含首包随机偏移）。报文 HMAC 标签覆盖 `total + slot + flow id + 时间戳`，且校验「收到的端口 == 声明的 slot」，所以包不能被挪到别的端口。必须在 6s 窗口内、来自同一源 IP 集齐声明的 `total` 个不同 slot 才算通过；时间戳仅接受 ±60s，已完成过的 flow id 会被记忆 15 分钟，重放不会二次开门。无效敲门**不回任何包**。
- **隐藏**：数据端口平时不绑定，只有 gate 打开时临时绑定；无会话/gate 过期后立即关闭。每个源 IP 的 HELLO 限速 20 次/分钟。
- **文件写入**：先全部写入临时文件再 rename；覆盖前备份到 `config/state/backups/<时间戳>/`；只删除自己上次管理过的文件（`managed.json`），不会误删用户文件；新文件权限 0600。
- **日志**：只记录 hash 前 16 位、端口、密钥指纹（HKDF 子密钥前 6 字节），不记录密钥、飞书凭据或 prompt 内容。

### 4.2 边界与注意事项

1. **公开二进制内含密钥**：公开发的 release 二进制里必然带着它的集群密钥（这是「编译期随机」的直接结果）。把公开二进制用于自己的私有集群并不安全——请用 `promptsync secret --set` 换成只有你知道的密钥（推荐每次发布后都换）。
2. **用户态端口敲门 ≠ 防火墙敲门**：本工具不修改 iptables/nftables/pf。扫描器看到端口是关闭的，但服务器本机上仍能看到进程；如果需要内核级隐藏，可在防火墙只放行敲门端口池 + 数据端口给 `promptsync` 用户。
3. **无 per-agent 身份**：所有 agent 共享集群密钥。任何拿到密钥的人都能读 prompt 集；如需区分设备，请为每台机器使用不同的 `cluster_secret` 与独立端口（多实例），或后续扩展为每设备密钥。
4. **UDP 可靠性**：本工具自带分片/ACK/重传，但极端丢包或 NAT 表项超时会失败并重试下一轮；不保证跨公网稳定，推荐内网、WireGuard/Tailscale 等加密隧道内使用（隧道 + 本工具加密 = 双层保护）。
5. **服务端可信**：服务端会覆盖 agent 本地 prompt，请只把长期在线、你信任的机器设为 server。
6. **飞书凭据只在本地**：`app_id`/`app_secret` 保存在每台机器自己的 `config/config.toml`（0600，git 忽略），不会编进二进制，也不会进 CI 产物。agent 侧离线告警也需要这份凭据（见第 5 节的安全取舍）。

---

## 5. 飞书（自建应用）：绑定、prompt 控制通道、离线告警

旧的"群自定义机器人 webhook"已经**完全移除**。现在所有飞书能力（发消息、读私聊、离线告警）都走一个**企业自建应用**。

### 5.1 一次性在飞书开放平台创建应用

1. 打开 [飞书开放平台](https://open.feishu.cn/app) → 创建**企业自建应用**；
2. 「添加应用能力」→ 启用**机器人**；
3. 「权限管理」至少授予：
   - `im:message:readonly`（读私聊消息，控制通道）
   - `im:message:send_as_bot`（回执 + 离线告警）
   - `im:chat:readonly`（绑定阶段列会话，建议）
   - `contact:user.id:readonly`（仅在使用邮箱/手机号回退绑定时需要）
4. 「版本管理与发布」→ 创建版本并发布（企业内可用）；
5. 把 `app_id` / `app_secret` 填到服务端 `config/config.toml` 的 `[feishu.app]`，并把 `[feishu] enabled = true`。

> 应用凭据只存在本机配置目录（0600），不会进入 git，也不会编译进二进制。

### 5.2 首次启动绑定（扫码 / 点链接）

服务端第一次启动时，会打印一个终端二维码和链接：

```
https://applink.feishu.cn/client/bot/open?appId=cli_xxxxxxxx
```

1. 用飞书扫码（或点开链接）进入**和机器人的私聊**；
2. 随便发一句"绑定"；
3. 服务端在后台轮询，检测到这条私聊消息后自动完成绑定；
4. 绑定结果写入 `config/feishu-binding.json`，`owner_open_id` 写回 `config.toml`。

如果 90 秒内没检测到（飞书有些租户不会把私聊会话列出来），会自动回退：提示你输入绑定用的**飞书邮箱或手机号**，服务端查到 `open_id` 后主动给机器人发一条消息，拿到私聊 `chat_id` 完成绑定（需要 `contact:user.id:readonly`）。

也可以随时手动重绑（`--reset` 会先忘掉当前的 owner/私聊，再重新扫码）：

```bash
promptsync feishu-bind
promptsync feishu-bind --reset
```

非交互环境（systemd/launchd/`--non-interactive`）不会阻塞等待，只打印链接和提示；之后在终端里跑一次 `feishu-bind` 即可。

### 5.3 用飞书私聊覆盖服务端 prompt（控制通道）

绑定后，**直接给机器人私聊发纯文本**即可：

- 只接受**纯文本**（`text` 消息）；富文本、图片、附件一律回"只接受纯文本"并忽略；
- **只接受你本人**（`open_id` 白名单）在**绑定私聊**里发的消息；群聊、其他人一律不读；
- 消息正文就是整个文件内容（原样写入，末尾统一补一个换行）；
- 覆盖前把旧文件备份成同目录的 `<文件名>.<UTC时间>.bak`（默认保留最近 50 份，`feishu.control.keep_backups` 可调，0 = 全部保留）；
- 内容与现有文件一致时不写盘、不产生新的 hash，只回"无变化"；
- 超过 `feishu.control.max_message_bytes`（默认 32 KiB）直接拒绝，不会截断；
- 服务端回一条回执：`✅ 已更新 <source id/相对路径>（xxx B，sha256 xxxxxxxx）`；
- 写盘后 2 秒内 watcher 重算 hash、epoch+1，所有 agent 在 10 秒内拉到新内容。

`sync.target` 指定"唯一受管文件"，格式 `<source id>/<相对路径>`。首次启动时如果它是空的，会自动找**唯一的非空** `system_prompt.md` 或 `SOUL.md`：

- 只有一个非空候选：写回 `sync.target`，并询问"以后只同步这一个文件吗？"（默认是，选是会把该 source 的 globs 收窄到这一个文件）；
- 有多个非空候选或一个都没有：只在日志里提示，请你手动设置 `sync.target`。

单文件模式下 bundle 里永远只有这一个文件；`sync.delete_removed = false` 保证以后缩小同步范围时不会删除 agent 上已有的其他文件。

先试运行可以设 `feishu.control.dry_run = true`：只回执、不落盘。

### 5.4 离线告警（同样走自建应用）

| 方向 | 触发 | 说明 |
|---|---|---|
| agent 检测服务端 | 连续 `offline_threshold_secs`（默认 120s）失败 | 应用发消息给 `owner_open_id`；恢复后发恢复通知（`notify_on_recovery`） |
| server 检测 agent | 已知 agent 超过阈值没有轮询（`server.monitor_agents = true`） | 防止「agent 机器直接挂了」时无人告警 |

告警只发一次（`feishu.repeat_alert_secs = 0`）；设为 600 则每 10 分钟重复提醒。

测试通道：

```bash
promptsync feishu-test                    # 给绑定的账号发一条测试消息
promptsync feishu-test --text "自定义内容"
```

> agent 只发告警、不读消息，所以它的配置里只需要 `[feishu.app]` 的 `app_id`、`app_secret`、`owner_open_id` 三项（`owner_open_id` 可在服务端用 `promptsync status --json` 查到），并保持 `[feishu] enabled = true`。
>
> **权限取舍**：飞书应用的权限是应用级的。agent 要自己发离线告警，就需要在自己的机器上配置同一个 `app_id`/`app_secret`（也就意味着那台机器上的凭据具备应用的全部权限）。如果你介意，可以：给 agent 单独创建一个"只发消息"的应用（`im:message:send_as_bot` 即可，不授予只读权限），在 agent 的配置里填那套凭据；服务端仍用完整的应用。两套凭据互不影响。

---

## 6. 配置参考

配置文件由 `templates/config.toml` 生成到配置目录；完整注释见模板本身。关键项：

```toml
cluster_secret = ""       # 空 = 使用编译进二进制的密钥；64 位 hex，多机一致

[server]
bind = "0.0.0.0"
port = 0                  # 0 = 由密钥推导
knock_ports = []          # 空 = 由密钥推导（12 个端口池）
gate_ttl_secs = 90
knock_window_secs = 6
max_sessions = 32
monitor_agents = true
monitor_interval_secs = 5
forget_agent_after_secs = 604800

[agent]
server = "127.0.0.1"
port = 0
knock_ports = []
poll_secs = 10
offline_threshold_secs = 120
agent_id = ""             # 空 = 主机名
handshake_timeout_secs = 4
request_timeout_secs = 8
knock_interval_ms = 55    # 随机延迟基准
knock_min = 3             # 每次随机选几个端口
knock_max = 6
knock_jitter_ms = 45      # 每个延迟 ±jitter，首包也有随机偏移
connect_attempts = 3

[feishu]
enabled = false
notify_on_recovery = true
timeout_secs = 10
repeat_alert_secs = 0

[feishu.app]
app_id = ""                # 飞书自建应用
app_secret = ""            # 只在本机配置目录
owner_open_id = ""         # 绑定后自动写入；离线告警也发给它
api_base = "https://open.feishu.cn"

[feishu.control]
poll_secs = 5              # 轮询绑定私聊的间隔
max_message_bytes = 32768  # 超过则拒绝覆盖
dry_run = false
bind_timeout_secs = 90
bind_contact = ""          # 可选：回退绑定的邮箱/手机号
keep_backups = 50          # 0 = 保留全部 .bak

[logging]
dir = ""                            # 空 = <配置目录>/logs
level = "info"
max_file_bytes = 5242880
keep_files = 3
stderr = true

[sync]
target = ""                # 唯一受管文件：<source id>/<相对路径>
max_bundle_bytes = 1048576
keep_backups = 10
follow_symlinks = false
delete_removed = false     # 源集合变小时不删除 agent 上旧文件

[[sync.sources]]
id = "cindy-bots"
root = "~/Library/Application Support/CindyGlobal/owners"
globs = ["*/bots/*/system_prompt.md"]
```

端口推导规则（server 与 agent 一致）：
`port = 20000 + HMAC-SHA256(HKDF(cluster_secret,"port-map-v1"), counter)[0..8] mod 40000`，
先算数据端口，再算 12 个敲门端口（池），去重后使用。每次敲门从池中随机抽取子集，所以观察到的端口/顺序/时序不会重复。

---

## 7. 日志、状态与备份

全部在配置目录内：

- 日志：`config/logs/server.log`、`config/logs/agent.log`，按大小轮转（默认 5 MiB × 3 份）。
  关键事件：启动参数（不含密钥）、配置目录、hash 变化与 diff、敲门成功/失败、会话建立、拉包字节数、文件增删改、离线/恢复告警。
- 状态：`config/state/`
  - server：`agents.json`（每个 agent 的最后心跳/告警状态）
  - agent：`agent-state.json`（最后成功时间、服务端/本地 hash、失败次数、最近错误）
- 备份：agent 每次覆盖前把旧文件放到 `config/state/backups/<UTC 时间戳>/<source id>/...`，默认保留 10 份。
- 查看：`promptsync status`（人类可读）或 `promptsync status --json`。

---

## 8. 开机自启动

### Linux（systemd user）

```bash
# 安装二进制、生成 config/、写入带绝对路径的 unit
PROJECT_DIR=~/workspace/promptSync sh packaging/install.sh ./target/release/promptsync agent
systemctl --user daemon-reload
systemctl --user enable --now promptsync-agent
loginctl enable-linger "$USER"     # 注销后继续运行
journalctl --user -u promptsync-agent -f
```

服务端把最后的 `agent` 换成 `server`（`promptsync-server`）。unit 里固定了 `WorkingDirectory` 和 `--config-dir`，所以不会因为工作目录变化而新建配置。

### macOS（launchd）

```bash
PROJECT_DIR=~/workspace/promptSync sh packaging/install.sh ./target/release/promptsync agent
launchctl load -w ~/Library/LaunchAgents/com.cindy.promptsync.agent.plist
tail -f ~/workspace/promptSync/config/logs/agent.log
```

也可以用 `packaging/install.sh` 一键安装二进制 + 生成服务文件（不自动 sudo）。

---

## 9. GitHub Actions

| 工作流 | 触发 | 内容 |
|---|---|---|
| `.github/workflows/ci.yml` | push / PR | 秘密扫描、`cargo fmt --check`、`clippy -D warnings`、`cargo test` |
| `.github/workflows/release.yml` | tag `v*` / 手动 | 交叉编译 x86_64 安装包并发布 |

release 矩阵（全部 x86_64）：`x86_64-unknown-linux-gnu`、`x86_64-unknown-linux-musl`（静态，适合 Alpine/最小镜像）、`x86_64-apple-darwin`（Intel Mac）、`x86_64-pc-windows-msvc`。产物含二进制、README、`templates/`、服务模板与 `SHA256SUMS`。

密钥策略：

- `prepare` job 生成**本次发布**的集群密钥（优先用仓库 secret `PROMPTSYNC_CLUSTER_SECRET`，否则 `openssl rand -hex 32`），通过 `::add-mask::` 隐藏，再传给所有矩阵任务编译，保证同一版本的各个平台二进制可以互通。
- **不会**把任何飞书凭据编进 CI 产物；飞书配置只存在于每台机器自己的配置目录。
- 仓库卫生：`.gitignore` 整目录忽略 `config/` 和 `secrets/`，并忽略本地状态/日志/备份、`.env`、`*.pem`/`*.key`/`*.secret`。CI 的守卫步骤会在跟踪文件里发现这些内容时直接失败。
- 建议：发布后在自己的集群里执行 `promptsync secret --set <只有你知道的密钥>`，不要让公开二进制里的密钥成为你的实际密钥。

本地构建时若想固定密钥（例如跨机器分平台编译）：

```bash
export PROMPTSYNC_BUILD_SECRET=$(openssl rand -hex 32)   # 记下来，两台机器都用它
cargo build --release
```

---

## 10. 故障排查

| 现象 | 排查 |
|---|---|
| 配置目录不对 / 找不到配置 | `promptsync status` 第一段就打印 `config dir`；用 `--config-dir` 或 `PROMPTSYNC_CONFIG_DIR` 固定 |
| 服务启动后生成了新的空配置 | 服务的工作目录变了；unit 里设置 `WorkingDirectory` 并传 `--config-dir <绝对路径>` |
| `no handshake answer` | 两端 `promptsync ports` 看数据端口与敲门端口池是否一致；`cluster_secret` 是否相同；防火墙是否放行整个 UDP 端口池 |
| `HELLO failed authentication (cluster secret mismatch?)` | 密钥不一致，用 `secret --show` / `secret --set` 对齐 |
| 每轮都拉包 | 本地有 agent 未配置的 source（日志有 `skipping ...`），或本地文件被反复改动 |
| `bundle too large` | 调大 `sync.max_bundle_bytes`（单条加密消息上限约 4.4 MiB，base64 后实际可传约 3 MiB） |
| 时间戳相关错误 | 两端系统时钟偏差：敲门容忍 ±60s，握手 ±600s，先校时（NTP） |
| 端口被占用 | `server.port` 与其他服务冲突；数据端口只在敲门后绑定，但配置端口仍需唯一 |
| 飞书绑定一直超时 | 有些租户不会返回私聊会话；等 90 秒后用邮箱/手机号回退，或直接 `promptsync feishu-bind` |
| 飞书返回 99991663 / permission denied | `app_id`/`app_secret` 不对，或应用没发布、没授予 `im:message:readonly` / `im:message:send_as_bot` |
| 发消息没反应 | 必须是在**绑定的私聊**里由你本人发**纯文本**；群聊、他人、富文本都会被忽略（日志里有原因） |
| 覆盖后 agent 没更新 | 确认 `sync.target` 指向的文件确实在 server 的 source glob 内，且 `promptsync status` 的 hash 已变化 |

调试：`--log-level debug` 启动，或 `RUST_BACKTRACE=1`。

> 旧版本把配置放在系统目录（macOS `~/Library/Application Support/promptsync`）。现在默认使用项目内 `config/`；如想沿用旧文件，把 `config.toml` 复制到新配置目录，或 `promptsync --config <旧文件> ...`。

---

## 11. 开发

```bash
cargo test              # 单元测试 + 真实 UDP 端到端测试（随机敲门/握手/拉取/漂移修复/拒绝错误密钥）
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

模块：

| 文件 | 职责 |
|---|---|
| `build.rs` | 编译期随机密钥、构建指纹 |
| `templates/config.toml` | 配置模板（首次启动复制到配置目录） |
| `src/paths.rs` | 配置目录解析、模板渲染、首次启动自动创建 |
| `src/interactive.rs` | 启动指引、已有配置确认、交互式修改/编辑器 |
| `src/config.rs` | TOML 配置模型、校验、密钥写入 |
| `src/crypto.rs` | 集群密钥、子密钥、端口池推导、随机敲门标签、X25519 握手、AEAD、重放窗口 |
| `src/wire.rs` | UDP 记录格式、分片、ACK bitmap、重传 |
| `src/knock.rs` | 随机敲门计划、state/gate、重放 burn、端口推导 |
| `src/server.rs` | 权威源监听、会话、bundle 下发、agent 监控 |
| `src/agent.rs` | 轮询、拉取、落盘、离线判定、飞书 |
| `src/prompts.rs` | glob 扫描、canonical hash、原子写入/备份/删除 |
| `src/feishu.rs` | 飞书自建应用客户端（token、收发消息、绑定查询） |
| `src/feishu_control.rs` | 绑定流程、私聊轮询、单文件覆盖 + .bak 备份 |
| `src/logx.rs` | 轮转日志 |

## License

MIT
