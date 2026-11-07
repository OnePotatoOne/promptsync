# promptsync

[![ci](https://github.com/OnePotatoOne/promptsync/actions/workflows/ci.yml/badge.svg)](https://github.com/OnePotatoOne/promptsync/actions/workflows/ci.yml)
[![release](https://github.com/OnePotatoOne/promptsync/actions/workflows/release.yml/badge.svg)](https://github.com/OnePotatoOne/promptsync/actions/workflows/release.yml)

在多台电脑之间**加密同步 prompt**（默认同步 Cindy 的 `system_prompt.md` / `SOUL.md`，也可配置任意 Markdown 目录）。

- **服务端（server）** 是唯一权威源：本地 prompt 一变，就重新计算 SHA-256 并递增 epoch。
- **客户端（agent）** 每 10 秒向服务端校验 hash；不一致就拉取整包，原子写入本地，记录日志。
- 传输走 **UDP**：先做**随机端口敲门**，敲门成功前数据端口根本不绑定；握手用 **X25519 + 预共享密钥认证**，数据用 **AES-256-GCM**，带防重放窗口。
- 连续 **2 分钟**失联自动通过**飞书自建应用**发离线告警（恢复后可选恢复通知）。
- 绑定后可以直接给机器人**私聊发纯文本**，服务端自动覆盖唯一那个 prompt 文件，agent 再自动同步。
- agent 拉取后**自动适配本机客户端**：Codex、Claude Code、Kimi、DeepSeek、Cindy 的全局指令文件一起更新，覆盖前自动备份。
- **首次启动自动生成随机集群密钥**并写入本机配置（同时打印一次）；仓库和发布产物里没有固定密钥。其他机器用同一串密钥或同一句口令对齐。
- **个人配置集中在一个目录**（默认 `./config`，空目录启动时自动从模板生成，整个目录被 git 忽略）。
- 单文件 Rust 二进制，本地编译；GitHub Actions 交叉编译各平台裸二进制。

> 这是「可信内网/自建服务器 + 自己的多台电脑」场景的工具，不是面向公网多租户的服务。安全边界见 [安全模型](#安全模型与边界)。

---

## 1. 快速开始

### 1.1 本地编译

```bash
cargo build --release
./target/release/promptsync --version
```

编译时 `build.rs` 只生成一个**非密钥**的构建指纹，用于日志里判断 server/agent 是否来自同一次构建；不会再生成或编译任何集群密钥。

首次运行 `promptsync server` 或 `promptsync agent` 时，程序会：

1. 生成 32 字节随机集群密钥并写回 `config.toml`（同时打印一次、给出配置文件路径）；
2. 在配置向导第 3 步允许你直接回车保留它，或粘贴/输入其他机器使用的同一密钥/口令。

飞书使用**自建应用**，`app_id`/`app_secret` 只保存在本机配置目录，**不会编进二进制**。

> Release 里直接是**裸可执行文件**（没有 tar.gz / zip），文件名带版本号：Linux/macOS 为 `promptsync-<版本>-<平台>`（如 `promptsync-0.2.5-macos-aarch64`），Windows 为 `promptsync-<版本>-windows-x86_64.exe`。配置模板已经编译进二进制，首次启动自动生成，不需要额外的 README、模板或安装脚本。下载后 `chmod +x` 即可运行。

Release 二进制本身不包含集群密钥；每台机器首次运行生成自己的密钥，复制 server 打印的那一串到 agent 即可。**不同机器默认互不信任**，这是刻意设计。

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

### 1.2.1 启动向导（server / agent）

`server` 和 `agent` 在终端里启动时会走一个**逐步向导**：一次只问一项，直接回车保留推荐值，最后给你一份摘要让你确认。不再需要额外的绑定命令。

- **服务端首次启动（5 步）**
  1. 监听地址与数据端口（0 = 由密钥自动推导）；
  2. 要同步的 prompt 文件：自动列出候选（`system_prompt.md` / `SOUL.md`），多个时用序号选一个，并问"以后只同步这一个文件吗"；
  3. 集群密钥：首次启动会自动生成随机密钥并打印一次（同时给出 `config.toml` 路径）；向导里只显示指纹，回车保留它，或粘贴/输入其他机器使用的同一密钥/口令；
  4. 飞书：确认启用 → 默认「一键创建」，点开链接确认后自动填好 `app_id` / `app_secret` 和 owner，并当场完成绑定；已有应用可打开 `https://open.feishu.cn/app` 查看全部应用后手动粘贴；
  5. 摘要确认：显示监听、受管文件、密钥、飞书状态，回车开始运行。
- **agent 首次启动（4 步）**
  1. 服务端地址与端口；2. 集群密钥（首次启动自动生成并打印，可粘贴 server 的密钥）；3. 飞书（一键创建会自动带接收人；手动粘贴应用时填一次 `owner_open_id`，留空则跳过告警）；4. 摘要确认。
- **首次启动的密钥**：server/agent 启动时若配置里没有密钥，会立即生成一个并打印完整 hex、指纹和配置文件路径；最后摘要还会再显示一次。以后用 `promptsync secret --show` 查看，或直接打开 `config.toml` 的 `cluster_secret`。
- **后续启动**：只问一句"直接使用已有配置启动？[Y/n]"；选 `n` 就重新进入向导（所以改配置、重绑飞书都走同一个入口）。
- 每一步都会**立即写回** `config/config.toml`（保留注释），中途退出也不会丢已填的内容。
- **不会打扰脚本和服务**：非 TTY、`--non-interactive`、或已用 `--server` / `--port` / `--bind` / `--once` 覆盖时，自动跳过向导。

```bash
promptsync --non-interactive agent --config-dir /srv/promptsync/config
```

### 1.3 启动服务端

任选一台长期在线的电脑（建议小主机/NAS）：

```bash
cd ~/workspace/promptSync
./target/release/promptsync server
```

首次运行会创建 `config/config.toml`，生成并打印本机集群密钥，然后进入逐步向导（见 [1.2.1](#121-启动向导server--agent)）。把这次打印的密钥复制到 agent（或让所有机器输入同一句口令）。飞书的一键创建和绑定就在向导第 4 步完成。日志会显示数据端口与敲门端口池（默认 12 个）；每次敲门随机选 3–6 个端口、随机顺序、随机间隔。数据端口**只有在敲门成功后才会被绑定**，扫描器看到的是「关闭」状态。

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

1. **复制 server 首次启动打印的密钥**（推荐）：server 启动时会打印完整 hex 和 `config.toml` 路径；把同一串粘贴到 agent 第 3 步，或运行 `promptsync secret --set "<这串>"`。
2. **输入同一句口令**：
   ```bash
   # 在向导第 3 步直接输入这句话即可；也可以命令行写入
   promptsync secret --set "我们家的同步口令"
   ```
   程序用 PBKDF2-HMAC-SHA256 从这句话推导密钥，所有机器输入**完全相同**的一句话（含空格、大小写）就会得到同一个密钥。不需要记十六进制。
3. **兼容旧方式**：`promptsync secret --set <64 位 hex>` 仍然有效（例如从旧配置迁移）。

```bash
promptsync secret --show        # 查看当前十六进制（注意保密，仅排障用）
promptsync secret --generate    # 生成一个新的随机 hex（高级用法）
```

只要最终密钥相同，端口池、敲门标签密钥、握手密钥都会自动一致；无需手工对齐端口。敲门的具体端口/顺序每次都随机，不依赖任何固定序列。

> **从 v0.2.4 及更早版本升级**：旧二进制使用编译进二进制的密钥，新版本不再使用。升级后请让所有机器都换到新版本，并把 server 首次启动打印的密钥（或同一句口令）填到每台 agent；否则会因密钥不同而握手失败。

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

### 2.1 自动适配本机客户端

agent 把拉到的 prompt 再写进本机已安装客户端的全局指令文件，覆盖前自动备份：

| 客户端 | 目标文件 | 覆盖目录的环境变量 |
|---|---|---|
| Kimi Code | `~/.kimi-code/AGENTS.md` | `KIMI_CODE_HOME` |
| DeepSeek Harness | `~/.dsh/AGENTS.md` | `DSH_HOME` |
| Codex CLI | `~/.codex/AGENTS.md` | `CODEX_HOME` |
| Claude Code | `~/.claude/CLAUDE.md` | `CLAUDE_CONFIG_DIR` |
| Cindy | `CindyGlobal/owners/*/bots/cindy-default/SOUL.md` | — |

- 选哪个 prompt：优先服务端 `sync.target`；否则最大的 `SOUL.md` → 最大的 `system_prompt.md` → 唯一的文件 → 最大的 Markdown。
- 只在客户端目录已存在（或目标文件已存在）时写入，不会凭空创建一堆目录。
- 旧文件备份为同目录的 `<文件名>.<UTC 时间>.bak`，保留 `sync.keep_backups` 份（0 = 全部保留）。
- 内容相同则跳过，不产生备份、不改 mtime。
- 关闭：`adapt_clients = false`；额外客户端：`adapt_paths = ["~/path/to/AGENTS.md"]`。
- 飞书私聊覆盖服务端 prompt 后，服务端本机的客户端也会立即适配。
- `promptsync status` 会列出当前识别到的客户端文件。

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

- **密钥不落地仓库/二进制**：每台机器首次启动时生成 32 字节随机集群密钥，写进本机 `config.toml`（0600），同时打印一次；`build.rs` 只算非密钥的构建指纹。仓库中没有任何固定口令或端口。
- **个人配置不进仓库**：默认配置目录 `./config` 整体被 `.gitignore` 忽略；CI 守卫会拒绝任何 `secrets/`、`config/`、`*.pem`、`*.key`、`.env` 等被跟踪。
- **握手**：临时 X25519（前向保密）+ 用集群密钥对完整报文做 HMAC-SHA256（双向认证、防中间人、防时钟外重放 ±600s）。
- **会话密钥**：HKDF-SHA256 从 ECDH 共享密钥 + 双方 nonce 派生，上下行各一把 AES-256-GCM 密钥。
- **记录层**：每个报文独立 nonce（方向前缀 + 单调计数），1024 位重放窗口；篡改即认证失败、静默丢弃。
- **端口敲门（随机化）**：集群密钥推导出 12 个端口的池；每次尝试由 agent 随机选 3–6 个、随机顺序、随机延迟（含首包随机偏移）。报文 HMAC 标签覆盖 `total + slot + flow id + 时间戳`，且校验「收到的端口 == 声明的 slot」，所以包不能被挪到别的端口。必须在 6s 窗口内、来自同一源 IP 集齐声明的 `total` 个不同 slot 才算通过；时间戳仅接受 ±60s，已完成过的 flow id 会被记忆 15 分钟，重放不会二次开门。无效敲门**不回任何包**。
- **隐藏**：数据端口平时不绑定，只有 gate 打开时临时绑定；无会话/gate 过期后立即关闭。每个源 IP 的 HELLO 限速 20 次/分钟。
- **文件写入**：先全部写入临时文件再 rename；覆盖前备份到 `config/state/backups/<时间戳>/`；只删除自己上次管理过的文件（`managed.json`），不会误删用户文件；新文件权限 0600。
- **日志**：只记录 hash 前 16 位、端口、密钥指纹（HKDF 子密钥前 6 字节），不记录密钥、飞书凭据或 prompt 内容。

### 4.2 边界与注意事项

1. **首次启动生成的密钥就是集群密钥**：release 二进制不含固定密钥；每台机器首次运行会生成并打印自己的密钥。把 server 的密钥复制到 agent，或所有机器输入同一句口令；密钥只存在本机 `config.toml`（0600），不要提交、不要发到公开群。
2. **用户态端口敲门 ≠ 防火墙敲门**：本工具不修改 iptables/nftables/pf。扫描器看到端口是关闭的，但服务器本机上仍能看到进程；如果需要内核级隐藏，可在防火墙只放行敲门端口池 + 数据端口给 `promptsync` 用户。
3. **无 per-agent 身份**：所有 agent 共享集群密钥。任何拿到密钥的人都能读 prompt 集；如需区分设备，请为每台机器使用不同的 `cluster_secret` 与独立端口（多实例），或后续扩展为每设备密钥。
4. **UDP 可靠性**：本工具自带分片/ACK/重传，但极端丢包或 NAT 表项超时会失败并重试下一轮；不保证跨公网稳定，推荐内网、WireGuard/Tailscale 等加密隧道内使用（隧道 + 本工具加密 = 双层保护）。
5. **服务端可信**：服务端会覆盖 agent 本地 prompt，请只把长期在线、你信任的机器设为 server。
6. **飞书凭据只在本地**：`app_id`/`app_secret` 保存在每台机器自己的 `config/config.toml`（0600，git 忽略），不会编进二进制，也不会进 CI 产物。agent 侧离线告警也需要这份凭据（见第 5 节的安全取舍）。

---

## 5. 飞书（自建应用）：绑定、prompt 控制通道、离线告警

旧的"群自定义机器人 webhook"已经**完全移除**。现在所有飞书能力（发消息、读私聊、离线告警）都走一个**企业自建应用**。

### 5.1 一键创建应用（推荐）

不需要提前去开放平台点一堆按钮。`promptsync server` 向导第 4 步、`promptsync agent` 向导第 3 步默认就是「一键创建」：

1. 程序向飞书申请一个设备码，打印一个链接和二维码：
   ```
   https://open.feishu.cn/page/cli?user_code=XXXX-XXXX&from=xdt-maker
   ```
2. 用飞书扫码或在浏览器打开，按提示**确认创建**（会自动创建个人助手类型的自建应用，启用机器人能力并带上所需权限）；
3. 程序在后台轮询，确认后自动拿到 `app_id`、`app_secret` 和你的 `open_id`，直接写进 `config.toml`；
4. 自动用你的 `open_id` 发一条消息，拿到私聊 `chat_id`，绑定完成——**不需要复制粘贴，也不需要先给机器人发消息**。

如果企业策略不允许一键创建，或者你想用已有应用，向导里选「已有应用，手动粘贴」，按提示填 `app_id` / `app_secret` 即可。手动创建时需要：

- 启用**机器人**能力；
- 权限：`im:message:readonly`、`im:message:send_as_bot`、`im:chat:readonly`；
- 创建版本并发布到企业内。

> 应用凭据只存在本机配置目录（0600），不会进入 git，也不会编译进二进制。

### 5.2 绑定与重新绑定

- **一键创建**：创建完成即自动绑定，写入 `config/feishu-binding.json`，`owner_open_id` 写回 `config.toml`。
- **手动粘贴凭据**：校验通过后，程序会打印机器人链接/二维码和一次性绑定码；你打开私聊，只发送这个绑定码即可完成绑定。普通私聊消息和绑定开始前的历史消息都不会获得控制权。若 90 秒内没检测到（部分租户不返回私聊会话），会回退让你输入飞书邮箱/手机号主动绑定。
- **服务启动后还没绑定**：不用重跑。服务端日志会输出有效期 15 分钟的一次性绑定码；你在飞书里用需要授权的账号向机器人私聊发送该码，就会自动完成绑定并开始工作。过期后日志会给出新码。
- **换账号 / 重新绑定**：重新运行 `promptsync server` 或 `promptsync agent`，在「直接使用已有配置启动？」处选 `n`，进入飞书步骤后选「继续使用这个应用？」否，再走一次一键创建或手动流程。没有单独的绑定命令。绑定记录同时核对 `app_id` 与 `owner_open_id`；更换应用或接收人后，旧绑定不会被继续使用。

非交互环境（systemd/launchd/`--non-interactive`）不会进入向导；在终端里手动跑一次 `promptsync server` 或 `promptsync agent` 配置即可。

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

`sync.target` 指定"唯一受管文件"，格式 `<source id>/<相对路径>`。向导第 2 步会扫描 `system_prompt.md` / `SOUL.md`：

- 只有一个非空候选：直接选中，并询问"以后只同步这一个文件吗？"（默认是，选是会把该 source 的 globs 收窄到这一个文件）；
- 有多个非空候选：列出序号让你选；一个都没有时允许手动输入 `sync.target`。

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

> agent 只发告警、不读消息，所以它的配置里只需要 `[feishu.app]` 的 `app_id`、`app_secret`、`owner_open_id` 三项，并保持 `[feishu] enabled = true`。运行 `promptsync agent` 的飞书步骤时，一键创建会自动填入接收人；手动粘贴应用凭据时，向导会要求填一次 `owner_open_id`（服务端 `promptsync status --json` 可查），留空则跳过离线告警。agent 不走扫码绑定：只发消息的应用没有读取私聊的权限，扫码发现不了会话，部分租户也不会返回 p2p 会话。
>
> **权限取舍**：飞书应用的权限是应用级的。agent 要自己发离线告警，就需要在自己的机器上配置同一个 `app_id`/`app_secret`（也就意味着那台机器上的凭据具备应用的全部权限）。如果你介意，可以：给 agent 单独创建一个"只发消息"的应用（`im:message:send_as_bot` 即可，不授予只读权限），在 agent 的配置里填那套凭据；服务端仍用完整的应用。两套凭据互不影响。

---

## 6. 配置参考

配置文件由 `templates/config.toml` 生成到配置目录；完整注释见模板本身。关键项：

```toml
cluster_secret = ""       # 首次启动自动生成并写回；也可填同一句口令（多机一致）或 64 位 hex

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
app_id = ""                # 飞书自建应用（向导可一键创建）
app_secret = ""            # 只在本机配置目录
owner_open_id = ""         # 绑定后自动写入；离线告警也发给它
api_base = "https://open.feishu.cn"

[feishu.control]
poll_secs = 5              # 轮询私聊的间隔（未绑定时也用它重试绑定）
max_message_bytes = 32768  # 超过则拒绝覆盖
dry_run = false
bind_timeout_secs = 90
bind_contact = ""          # 可选：手动绑定时回退用的邮箱/手机号
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
adapt_clients = true       # 自动适配本机 Codex/Claude/Kimi/DeepSeek/Cindy 的指令文件
adapt_paths = []           # 额外目标文件（绝对路径或 ~/...）

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
- 客户端适配备份：覆盖 `~/.codex/AGENTS.md` 等文件前，在同目录生成 `<文件名>.<UTC 时间>.bak`，保留 `sync.keep_backups` 份。
- 查看：`promptsync status`（人类可读）或 `promptsync status --json`。

---

## 8. 开机自启动

### Linux（systemd user）

```bash
# 需要源码仓库里的 packaging/install.sh（release 只有裸二进制）
PROJECT_DIR=~/workspace/promptSync sh packaging/install.sh ./target/release/promptsync agent
systemctl --user daemon-reload
systemctl --user enable --now promptsync-agent
loginctl enable-linger "$USER"     # 注销后继续运行
journalctl --user -u promptsync-agent -f
```

服务端把最后的 `agent` 换成 `server`（`promptsync-server`）。unit 里固定了 `WorkingDirectory` 和 `--config-dir`，所以不会因为工作目录变化而新建配置。

### macOS（launchd）

```bash
# 需要源码仓库里的 packaging/install.sh（release 只有裸二进制）
PROJECT_DIR=~/workspace/promptSync sh packaging/install.sh ./target/release/promptsync agent
launchctl load -w ~/Library/LaunchAgents/com.cindy.promptsync.agent.plist
tail -f ~/workspace/promptSync/config/logs/agent.log
```

也可以用源码仓库里的 `packaging/install.sh` 一键安装二进制 + 生成服务文件（不自动 sudo；release 只包含可执行文件，不含该脚本）。

---

## 9. GitHub Actions

| 工作流 | 触发 | 内容 |
|---|---|---|
| `.github/workflows/ci.yml` | push / PR | 秘密扫描、`cargo fmt --check`、`clippy -D warnings`、`cargo test` |
| `.github/workflows/release.yml` | tag `v*` / 手动 | 交叉编译各平台裸二进制并发布 |

发一个新版本：

```bash
git tag -a v0.1.0 -m "promptsync v0.1.0"
git push origin v0.1.0
```

release 矩阵：`x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`、`x86_64-apple-darwin`、`aarch64-apple-darwin`、`x86_64-pc-windows-msvc`。产物就是带版本号的裸二进制（`promptsync-<版本>-linux-x86_64`、`promptsync-<版本>-macos-aarch64`、`promptsync-<版本>-windows-x86_64.exe` 等）加一个 `SHA256SUMS`，没有压缩包，也不再提供 musl 静态版。

密钥策略：

- `prepare` job 只读取并校验版本号，不再生成或传递任何集群密钥；每个平台的二进制都不含密钥。
- **不会**把任何飞书凭据编进 CI 产物；飞书配置只存在于每台机器自己的配置目录。
- 仓库卫生：`.gitignore` 整目录忽略 `config/` 和 `secrets/`，并忽略本地状态/日志/备份、`.env`、`*.pem`/`*.key`/`*.secret`。CI 的守卫步骤会在跟踪文件里发现这些内容时直接失败。
- 每台机器首次启动生成自己的随机密钥；把 server 打印的密钥复制到 agent，或统一输入同一句口令。

本地构建不再需要固定密钥；server 和 agent 分别首次启动时生成，随后用同一密钥/口令对齐即可。

---

## 10. 故障排查

| 现象 | 排查 |
|---|---|
| 配置目录不对 / 找不到配置 | `promptsync status` 第一段就打印 `config dir`；用 `--config-dir` 或 `PROMPTSYNC_CONFIG_DIR` 固定 |
| 服务启动后生成了新的空配置 | 服务的工作目录变了；unit 里设置 `WorkingDirectory` 并传 `--config-dir <绝对路径>` |
| `no handshake answer` | 两端 `promptsync ports` 看数据端口与敲门端口池是否一致；`cluster_secret` 是否相同；防火墙是否放行整个 UDP 端口池 |
| `HELLO failed authentication (cluster secret mismatch?)` | 口令不一致，所有机器输入同一句话（`secret --set "同一句口令"`）；旧 64 位 hex 也能用 |
| 每轮都拉包 | 本地有 agent 未配置的 source（日志有 `skipping ...`），或本地文件被反复改动 |
| `bundle too large` | 调大 `sync.max_bundle_bytes`（单条加密消息上限约 4.4 MiB，base64 后实际可传约 3 MiB） |
| 时间戳相关错误 | 两端系统时钟偏差：敲门容忍 ±60s，握手 ±600s，先校时（NTP） |
| 端口被占用 | `server.port` 与其他服务冲突；数据端口只在敲门后绑定，但配置端口仍需唯一 |
| 飞书没绑定成功 | 一键创建会自动绑定；手动粘贴凭据时，用授权账号向机器人私聊发送向导或日志中的一次性绑定码即可，服务启动后也会持续等待绑定，不必重跑 |
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
| `build.rs` | 生成非密钥的构建指纹 |
| `templates/config.toml` | 配置模板（首次启动复制到配置目录） |
| `src/paths.rs` | 配置目录解析、模板渲染、首次启动自动创建 |
| `src/interactive.rs` | 启动指引、已有配置确认、交互式修改/编辑器 |
| `src/config.rs` | TOML 配置模型、校验、密钥写入 |
| `src/crypto.rs` | 集群密钥、子密钥、端口池推导、随机敲门标签、X25519 握手、AEAD、重放窗口 |
| `src/wire.rs` | UDP 记录格式、分片、ACK bitmap、重传 |
| `src/knock.rs` | 随机敲门计划、state/gate、重放 burn、端口推导 |
| `src/server.rs` | 权威源监听、会话、bundle 下发、agent 监控 |
| `src/agent.rs` | 轮询、拉取、落盘、离线判定、飞书 |
| `src/adapters.rs` | 把同步到的 prompt 适配到 Codex/Claude/Kimi/DeepSeek/Cindy 的指令文件 |
| `src/prompts.rs` | glob 扫描、canonical hash、原子写入/备份/删除 |
| `src/feishu.rs` | 飞书自建应用客户端（token、收发消息、绑定查询） |
| `src/feishu_control.rs` | 绑定流程、私聊轮询、单文件覆盖 + .bak 备份 |
| `src/logx.rs` | 轮转日志 |

## License

MIT
