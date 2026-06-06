# Callsign

[English](README.md) | 简体中文

Callsign 是一个轻量级 Overlay 网络原型，采用控制面与数据面分离架构。

项目聚焦于快速协议验证、严格的 token 访问控制，以及可落地的反向代理部署路径。

## 特性

- 分层架构：Flask 控制面 + WebSocket 隧道面 + Windows 客户端
- 控制/隧道接口均基于 token 鉴权（必须携带 `X-Access-Token`）
- 支持会话 bootstrap、heartbeat、服务端验证流程
- 支持 echo 模式（验证传输）和 tun 模式（路由转发）
- Windows GUI 提供托盘控制、配置管理和单实例保护
- 通过 systemd (`callsign-nat.service`) 提供 Linux 开机 NAT 恢复能力

## 架构

1. 控制面 (`server/control`)
- Bootstrap
- 会话签发
- 心跳与 token 校验

2. 隧道面 (`server/tunnel`)
- 鉴权 WebSocket 入口
- 数据包传输（echo / tun）
- 基于控制面的 bearer 校验

3. 客户端 (`client/windows`)
- Bootstrap 与 heartbeat 循环
- 隧道连接生命周期
- 适配器抽象（mock / Wintun）

详细设计见 [docs/architecture.md](docs/architecture.md)

## 快速开始

### 1) 环境准备

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2) 最小配置

```powershell
Copy-Item .env.example .env
```

至少设置：

```text
CALLSIGN_ACCESS_TOKEN=<strong-random-token>
```

### 3) 启动服务

控制面：

```powershell
./scripts/start-control.ps1
```

隧道面：

```powershell
./scripts/start-tunnel.ps1
```

客户端：

```powershell
./scripts/start-client.ps1 -ControlUrl https://overlay.example.com
```

仅用于本地明文测试：

```powershell
./scripts/start-client.ps1 -ControlUrl http://127.0.0.1:5000 -TunnelUrl ws://127.0.0.1:8443/connect-ws -AllowInsecure
```

## 构建

```powershell
./scripts/build-exe.ps1
```

输出：

- `dist/callsign/callsign.exe`
- `dist/callsign-windows-arm64.zip`

当前为 onedir 打包，请分发 zip 或完整目录，不要只分发单个 exe。

## 配置

核心变量：

- `CALLSIGN_ACCESS_TOKEN`：直接 token 值
- `CALLSIGN_ACCESS_TOKEN_FILE`：token 文件路径（默认 `/etc/callsign/access_token`）
- `CALLSIGN_TUNNEL_PATH`：WebSocket 路径（需与 control/tunnel/proxy 一致）

控制面变量：

- `CALLSIGN_SESSION_TTL`（默认 `3600`）
- `CALLSIGN_TUNNEL_PUBLIC_URL`

隧道面变量：

- `CONTROL_VALIDATE_URL`（默认 `http://127.0.0.1:5000/api/v1/validate`）
- `CALLSIGN_TUN_MODE`（`echo` 或 `tun`）
- `CALLSIGN_TUN_INTERFACE`（默认 `tun0`）
- `CALLSIGN_TUN_LOCAL_CIDR`（默认 `10.99.0.1/24`）

## 服务器部署说明

- 反向代理基线：`deploy/nginx.conf.example`
- NAT 持久化资产：
  - `deploy/systemd/callsign-nat.service`
  - `deploy/systemd/callsign-nat-setup.sh`

推荐 Linux token 初始化：

```bash
sudo install -d -m 700 /etc/callsign
sudo sh -c 'umask 077; [ -s /etc/callsign/access_token ] || python3 - <<"PY" > /etc/callsign/access_token
import secrets
print(secrets.token_urlsafe(32))
PY'
sudo chmod 600 /etc/callsign/access_token
```

在 `/etc/proxy-server.env` 设置：

```bash
CALLSIGN_ACCESS_TOKEN_FILE=/etc/callsign/access_token
```

## 测试

执行全量回归：

```powershell
.\.venv\Scripts\python.exe scripts/server_auth_surface_smoke.py
.\.venv\Scripts\python.exe scripts/gui_full_regression_test.py
.\.venv\Scripts\python.exe scripts/gui_startup_elevation_test.py
.\.venv\Scripts\python.exe scripts/gui_single_instance_smoke.py
.\.venv\Scripts\python.exe scripts/gui_tray_smoke_test.py
.\.venv\Scripts\python.exe scripts/gui_tray_runtime_smoke.py
```

## 安全清单（推送前）

- 确保真实 token 不进入 git 历史
- `.env`、`.env.*`、`deploy/proxy-server.env` 只保留在本地
- `client_profiles.json`、`*.log`、`*.ppk` 不纳入版本控制
- 凭据一旦出现在终端历史、日志或截图中，应立即轮换

## 仓库结构

- `server/control`：控制面服务
- `server/tunnel`：隧道面服务
- `client/windows`：Windows GUI 与 agent
- `scripts`：构建、运行、部署、测试脚本
- `deploy`：nginx 与 systemd 部署资产
- `third_party/wintun`：Wintun 二进制与许可证

## 项目状态

Callsign 当前处于原型阶段，重点是行为验证与渐进式安全加固。

暂不在当前范围：

- 生产级策略引擎
- 端到端 mTLS 身份体系
- 完整可观测与 SRE 运维体系
