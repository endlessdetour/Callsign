# Callsign

[English](README.md) | 简体中文

Callsign：一个轻量级的 HTTP/3 Overlay 网络原型。

Callsign 是一个开源的 Overlay 网络原型，采用控制面与数据面分离架构。

设计目标：
- 快速验证协议与路由行为
- 仅通过反向代理暴露 443 端口
- 支持逐步加固以适配真实部署

当前实现包括：Windows GUI 客户端、控制服务（Flask）、隧道服务（WebSocket）。

## 1) 项目定位

Callsign 定位为通用 Overlay 网络项目，接近基础设施网络工具与私有连接平台。

## 2) 项目能力

- Windows GUI 客户端与配置管理
- 主窗口与托盘可发起/停止连接
- 单实例保护（避免重复启动多个窗口）
- 管理员权限自动重启路径（用于需要提权的操作）
- 基于 Wintun 的适配器与路由编程路径
- 控制面 bootstrap、heartbeat、token 校验
- 数据面鉴权 WebSocket 传输
- 基础安全策略：
  - 控制/隧道服务强制访问 token
  - 未授权或无效请求默认拒绝（控制面返回 444）

## 3) 当前范围与非目标

该项目目前仍为原型，主要验证控制与传输行为，尚非完整生产网络平台。

暂未完成：
- 生产级转发策略引擎
- 端到端证书身份（mTLS）
- 完整可观测性与 SRE 运维体系

## 4) 高层架构

1. 控制面（Flask）
- 设备 bootstrap
- 会话签发
- 心跳与 token 校验

2. 数据面（WebSocket）
- 鉴权隧道入口
- 二进制帧传输
- echo 模式验证与 tun 模式能力路径

3. 客户端（Windows）
- bootstrap 与 heartbeat 循环
- 隧道连接与帧交换
- 适配器抽象（Mock / Wintun）

另见：docs/architecture.md

## 5) 仓库结构

- server/control: Flask 控制面服务
- server/tunnel: WebSocket 隧道服务
- client/windows: Windows GUI 与 agent
- scripts: 启动/构建/测试脚本
- deploy: 反向代理与部署示例
- third_party/wintun: Wintun 运行时与许可证

## 6) 安全模型（重要）

Callsign 使用单访问 token 模型。

必需控制项：
- 控制与隧道服务都必须有 access token
  - 优先读取 `CALLSIGN_ACCESS_TOKEN`
  - 未设置时回退读取 `CALLSIGN_ACCESS_TOKEN_FILE`（默认 `/etc/callsign/access_token`）
- 客户端请求控制/隧道服务时必须携带 `X-Access-Token`
- 控制面未授权/无效请求返回 444；隧道握手拒绝使用 WebSocket 兼容的标准 HTTP 状态码

运维含义：
- 链路任一点 token 来源缺失或不一致，都会被拒绝。

## 7) 前置依赖

- Windows 11（用于客户端开发与 GUI 打包）
- Python 3.14.x（与运行时主次版本一致）
- PowerShell
- 可选：PyInstaller（在 venv 中安装）

## 8) 本地快速启动（原型）

### 8.1 创建环境

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 8.2 准备配置文件

```powershell
Copy-Item .env.example .env
```

编辑 `.env`，至少设置：
- `CALLSIGN_ACCESS_TOKEN`

### 8.3 设置必需环境变量（可选覆盖）

```powershell
$env:CALLSIGN_ACCESS_TOKEN="replace-with-strong-random-token"
$env:CALLSIGN_TUNNEL_PATH="/connect-ws"
$env:CALLSIGN_TUNNEL_PUBLIC_URL="wss://overlay.example.com/connect-ws"
```

### 8.4 启动服务

终端 A（control）：

```powershell
./scripts/start-control.ps1
```

终端 B（tunnel）：

```powershell
./scripts/start-tunnel.ps1
```

终端 C（client agent）：

```powershell
./scripts/start-client.ps1 -ControlUrl https://overlay.example.com
```

仅限本地明文测试：

```powershell
./scripts/start-client.ps1 -ControlUrl http://127.0.0.1:5000 -TunnelUrl ws://127.0.0.1:8443/connect-ws -AllowInsecure
```

## 9) Windows GUI 客户端

源码运行：

```powershell
./scripts/start-client-gui.ps1
```

主要行为：
- 关闭按钮最小化到托盘
- 托盘菜单支持 connect/disconnect/show/exit
- 主窗口包含显式 Exit 按钮
- 已运行时再次启动仅提示，不打开第二个窗口

## 10) 构建 Windows 可执行文件

```powershell
./scripts/build-exe.ps1
```

输出：
- dist/callsign/callsign.exe
- dist/callsign-windows-arm64.zip

说明：
- callsign.exe 是用户入口
- agent.exe 是随 GUI 打包的后台辅助进程
- 当前为 onedir 包，不可只分发单个 callsign.exe 或 agent.exe
- 请分发 dist/callsign-windows-arm64.zip（或整个 dist/callsign 目录）

## 11) 配置说明

### 核心变量

仅使用 CALLSIGN_* 命名。

- CALLSIGN_ACCESS_TOKEN
  - 用途：控制/隧道请求的直接 token 值
  - 必需：否（若 `CALLSIGN_ACCESS_TOKEN_FILE` 已设置且有效）

- CALLSIGN_ACCESS_TOKEN_FILE
  - 用途：控制/隧道服务读取 token 的文件路径
  - 必需：服务器部署推荐
  - 默认：/etc/callsign/access_token

- CALLSIGN_TUNNEL_PATH
  - 用途：隧道 WebSocket 路径（需与 control/tunnel/proxy 保持一致）
  - 必需：推荐
  - 示例：/connect-ws

### 控制服务

- CALLSIGN_SESSION_TTL
  - 用途：会话 token TTL（秒）
  - 默认：3600

- CALLSIGN_TUNNEL_PUBLIC_URL
  - 用途：bootstrap 返回给客户端的公网 WSS 地址
  - 示例：wss://overlay.example.com/connect-ws

### 隧道服务

- CONTROL_VALIDATE_URL
  - 用途：控制面 bearer 校验地址
  - 默认：http://127.0.0.1:5000/api/v1/validate

- CALLSIGN_TUN_MODE
  - 用途：echo 或 tun
  - 默认：echo

- CALLSIGN_TUN_INTERFACE
  - 用途：隧道服务使用的 tun 网卡名
  - 默认：tun0

- CALLSIGN_TUN_LOCAL_CIDR
  - 用途：路由/NAT 使用的 tun 网关 CIDR
  - 默认：10.99.0.1/24

## 12) NAT 持久化（Linux 服务器）

- 部署会自动安装并启用 callsign-nat.service
- callsign-nat.service 在开机时运行 /usr/local/bin/callsign-nat-setup.sh
- 会强制启用 ip_forward，并设置 MASQUERADE 与 FORWARD 规则

## 13) 反向代理与暴露策略

以 deploy/nginx.conf.example 为基线。

加固建议：
- 公网仅暴露 443
- 应用进程仅监听 localhost/私网
- 隧道路径使用非默认值并全链路保持一致
- 增加来源白名单（如可信 CDN/边缘）
- 增加限速与连接上限

## 14) 测试

GUI 与行为回归：
- scripts/gui_startup_elevation_test.py
- scripts/gui_full_regression_test.py
- scripts/gui_tray_smoke_test.py
- scripts/gui_tray_runtime_smoke.py
- scripts/gui_single_instance_smoke.py

服务鉴权冒烟：
- scripts/server_auth_surface_smoke.py

示例：

```powershell
.\.venv\Scripts\python.exe scripts/server_auth_surface_smoke.py
.\.venv\Scripts\python.exe scripts/gui_full_regression_test.py
```

## 15) 故障排查

### GUI 启动但无法连接

- 检查客户端终端是否设置 `CALLSIGN_ACCESS_TOKEN`
- 校验 control URL 与 tunnel URL/path 一致
- 检查反向代理是否设置 WebSocket 升级头

### 请求总被拒绝

- 确认 `X-Access-Token` 全链路正确
- 确认 control/tunnel 使用同一 token 来源

### Wintun 或路由接管异常

- 以管理员运行 GUI
- 核查 Wintun DLL 位置与许可文件
- 先测 echo，再测 tun

### Windows 资源管理器图标未更新

- 重新构建后重开资源管理器窗口
- 必要时刷新图标缓存

## 16) 开源与许可证说明

- 发布前检查 third_party/wintun 的许可条款
- 发布产物中保留第三方声明
- 商业化前核验依赖许可证

## 17) 推送前安全清单（Git）

推送到 GitHub 前请确认：
- 未提交真实 key/token
  - 示例中的 `CALLSIGN_ACCESS_TOKEN` 必须保留占位值
  - `CALLSIGN_ACCESS_TOKEN_FILE` 仅应指向服务器本地路径（如 `/etc/callsign/access_token`）
- 未提交私有部署 env 文件
  - `.env`、`.env.*`、`deploy/proxy-server.env` 仅本地保存
- 未提交本地 profile 或运行日志
  - `client_profiles.json`、`*.log` 不应入库
- 未提交私钥文件
  - `*.ppk` 等 SSH 私钥文件必须在仓库外
- 凡是在脚本/终端历史/截图里出现过的凭据都应轮换
- 发布前重新跑回归测试
  - `scripts/gui_full_regression_test.py`
  - `scripts/server_auth_surface_smoke.py`

Git 风险提示：
- Git 历史默认不可逆，真实 token 一旦推送应视为泄露并立刻轮换
- 每次提交前检查 staged diff，确保没有敏感文件
- 若误提交敏感信息，除改写历史并强推外，仍需执行凭据轮换

## 18) 服务端 Token 初始化（推荐）

Linux 服务器建议将 token 持久化为 root-only 文件：

```bash
sudo install -d -m 700 /etc/callsign
sudo sh -c 'umask 077; [ -s /etc/callsign/access_token ] || python3 - <<"PY" > /etc/callsign/access_token
import secrets
print(secrets.token_urlsafe(32))
PY'
sudo chmod 600 /etc/callsign/access_token
```

在 `/etc/proxy-server.env` 中设置：

```bash
CALLSIGN_ACCESS_TOKEN_FILE=/etc/callsign/access_token
```

本地开发可直接设置 `CALLSIGN_ACCESS_TOKEN`，服务器部署建议优先文件读取。

## 19) 路线图

- mTLS 设备身份与短时效签名凭据
- 更稳健的 NAT/转发数据面行为
- 更完善的诊断、指标与生产部署模板
- 桌面端安装器与更新通道
