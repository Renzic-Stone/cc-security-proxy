# CC Security Proxy

在 Coding Agent 和不可信的第三方 API 中转站之间架设安全代理，拦截响应中的恶意脚本注入。

## 为什么需要这个

第三方 API 中转站靠转卖算力差价赚钱，这种商业模式本身没问题。但有些中转站为了额外收益，会在返回给你的响应里注入恶意脚本——比如往 Windows 启动目录写 VBS 文件弹广告。你的 Coding Agent 会忠实地执行这些指令，而大多数人习惯一路点 Yes。

CC Security Proxy 在你的 Agent 和中转站之间加了一层安全过滤，提供三种强度的防护。

## 三种模式

| 模式 | 延迟 | 安全性 | 原理 |
|------|------|--------|------|
| **default** | 无延迟 | 最低 | 纯转发 + 日志记录，不拦截 |
| **protected** | 2-5 秒 | 高 | 静态扫描 → Docker 沙箱执行 → 行为分析 |
| **smart** | 1-3 秒 | 最高 | 静态预扫 → LLM 分流 → 不确定才进沙箱 |

### default — 默认模式

全部放行，但会用 16 条规则扫描并记录可疑内容。适合先跑一段时间，摸清你的中转站到底干不干净，再决定开不开拦截。

### protected — 保护模式

从响应中提取代码块，扔进 Docker 沙箱里执行。沙箱环境：
- 网络完全隔离（`--network=none`）
- 移除全部 Linux capabilities
- 禁止提权（`--security-opt=no-new-privileges`）
- 128MB 内存上限，30 秒超时

执行完后检查容器变更，触发以下行为则拦截：
- 向持久化目录写文件（Startup、LaunchAgents、crontab、systemd）
- 尝试建立网络连接
- 修改 Shell 配置文件（.bashrc、.zshrc、.profile）
- 下载并执行、提权操作

### smart — 智能模式（推荐日常使用）

三步递进，兼顾速度和安全性：

1. **静态预扫（零延迟）** — 抓到反向 shell、base64 解码执行等高危特征直接拦截；完全干净的短文本直接放行
2. **LLM 分流（~1 秒）** — 调一次便宜模型做分类，返回 `SAFE`（安全）/ `SUSPICIOUS`（可疑）/ `MALICIOUS`（恶意）：
   - 高置信度 SAFE → 直接放行
   - 高置信度 MALICIOUS → 直接拦截
   - 拿不准 → 进入第三步
3. **沙箱兜底（~2-5 秒）** — 只有模型不确定时才启动沙箱，尽量减少延迟

LLM 调用失败或超时 → 自动降级到沙箱，确保安全不断档。用 gpt-4o-mini 的话一次判断不到一分钱。

## 快速开始

### 环境要求

- Python 3.11+
- Docker（protected/smart 模式需要）

### 安装

```bash
git clone https://github.com/Renzic-Stone/cc-security-proxy.git
cd cc-security-proxy
pip install -e .
```

### 配置

```bash
cp .env.example .env
# 编辑 .env 填入配置
```

最简 `.env`：
```env
UPSTREAM_URL=https://your-relay.example.com
MODE=smart
LLM_API_KEY=sk-your-key-here
LLM_MODEL=gpt-4o-mini
```

如果你的 LLM 供应商不是 OpenAI（比如你用 DeepSeek、Qwen 等国产模型），改 `LLM_BASE_URL` 就行：
```env
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_MODEL=deepseek-chat
```

### 启动

```bash
# 智能模式（推荐）
cc-security-proxy --mode smart

# 保护模式（纯沙箱，不用 LLM）
cc-security-proxy --mode protected

# 默认模式（只观察不拦截）
cc-security-proxy --mode default

# 自定义端口和上游
cc-security-proxy --port 9090 --upstream https://other-relay.com
```

### 配置 Coding Agent

把 Agent 的 API 地址指向代理：

```bash
# Claude Code
export ANTHROPIC_BASE_URL=http://localhost:8080

# 其他 Agent 在设置里改 API Base URL
# API_BASE_URL=http://localhost:8080
```

## 架构

```
Coding Agent ──POST /v1/chat/completions──▶ CC Security Proxy :8080
                                                  │
                                                  ├── 静态扫描（始终执行）
                                                  │
                                                  ├── 模式分流:
                                                  │   ├── default: 转发
                                                  │   ├── protected: Docker 沙箱
                                                  │   └── smart: LLM → 沙箱
                                                  │
                                                  ▼
                                          放行 / 拦截
                                                  │
                                                  ▼
                                         上游中转站
```

请求流程：
1. Agent 发请求到 `localhost:8080/v1/chat/completions`
2. 代理原样转发给上游中转站
3. 上游返回响应，代理提取全部文本内容
4. 静态扫描 → 模式判断 → 决定放行还是拦截
5. 放行返回原始响应；拦截返回 403 + 原因

## 静态扫描器

所有模式下都会跑的 16 条正则规则：

| 规则 | 说明 | 严重度 |
|------|------|--------|
| `startup_write_win` | Windows 启动目录写入 | 0.95 |
| `startup_write_unix` | Linux autostart 写入 | 0.95 |
| `launch_agent_macos` | macOS LaunchAgent 持久化 | 0.95 |
| `shell_pipe_exec` | curl/wget 管道到 shell | 0.90 |
| `base64_decode_exec` | Base64 解码执行 | 0.90 |
| `registry_persistence` | Windows 注册表 Run 键 | 0.90 |
| `crontab_manipulation` | Crontab 篡改 | 0.85 |
| `download_and_execute` | 下载并执行 | 0.85 |
| `reverse_shell` | 反向 shell | 0.95 |
| `eval_obfuscated` | 混淆 eval/exec | 0.80 |
| `vbs_powershell_launch` | VBS/PS1 脚本创建 | 0.85 |
| `sudo_priv_escalation` | 提权尝试 | 0.80 |
| `rm_rf_destructive` | 破坏性 rm -rf | 0.70 |
| `hidden_file_write` | 写入隐藏/系统文件 | 0.75 |
| `dns_exfiltration` | DNS 数据外泄 | 0.85 |
| `socket_connect` | 原始 socket 连接 (C2) | 0.80 |

## 端点

| 端点 | 说明 |
|------|------|
| `GET /health` | 代理状态、当前模式、上游地址、统计 |
| `GET /stats` | 请求总数/放行/拦截/错误计数 |
| `POST /v1/*` | API 透传（支持所有 HTTP 方法） |
| `* /*` | 兜底透传 |

## 运行测试

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## 配置参考

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `PROXY_HOST` | `127.0.0.1` | 监听地址 |
| `PROXY_PORT` | `8080` | 监听端口 |
| `UPSTREAM_URL` | 必填 | 中转站地址 |
| `MODE` | `smart` | `default` / `protected` / `smart` |
| `LLM_API_KEY` | — | LLM API 密钥（smart 模式必填） |
| `LLM_BASE_URL` | `https://api.openai.com/v1` | LLM 接口地址 |
| `LLM_MODEL` | `gpt-4o-mini` | 模型名称 |
| `LLM_TIMEOUT` | `10` | LLM 请求超时（秒） |
| `SANDBOX_TIMEOUT` | `30` | 沙箱执行超时（秒） |
| `SANDBOX_IMAGE` | `cc-security-sandbox` | Docker 镜像名 |
| `LOG_LEVEL` | `INFO` | 日志级别 |

## 局限

- 沙箱功能需要 Docker，Windows 上装 Docker Desktop
- LLM 判断不是铁壁——高度混淆的 payload 可能绕过
- 代理会增加延迟，尤其是 protected 模式。可根据需要调整超时
- 只检查 API 响应中的文本内容，二进制响应直接放行
- 你的 Coding Agent 需要支持自定义 API Base URL

## 项目结构

```
cc-security-proxy/
├── src/cc_security_proxy/
│   ├── cli.py              # 命令行入口
│   ├── config.py           # 配置加载 (.env + 环境变量)
│   ├── proxy.py            # aiohttp 服务器
│   ├── handler.py          # 请求路由 + 安全分流
│   ├── upstream.py         # 转发请求到中转站
│   ├── scanner.py          # 16 条静态正则规则
│   ├── modes/
│   │   ├── default_mode.py # 只记录不拦截
│   │   ├── protected_mode.py # Docker 沙箱执行
│   │   └── smart_mode.py   # LLM 分流 + 沙箱兜底
│   ├── sandbox/
│   │   ├── executor.py     # Docker 容器生命周期
│   │   ├── rules.py        # 沙箱行为分析
│   │   └── Dockerfile      # 沙箱镜像
│   └── llm/
│       ├── client.py       # OpenAI 兼容客户端
│       └── prompts.py      # 安全审计提示词
├── tests/                  # 25 个测试
├── examples/               # 恶意/安全 payload 样例
└── sandbox/                # 完整沙箱 Docker 构建上下文
```

## License

MIT
