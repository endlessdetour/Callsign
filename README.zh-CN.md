# Callsign

[English](README.md) | 简体中文

Callsign 是一个轻量级 Overlay 网络原型，内置用于用户与访问管理的管理控制台。

## 功能特性

- **Overlay 隧道** —— 基于 WebSocket 的控制面/隧道面，按设备分配会话令牌，使用 Linux `tun` 数据通道。
- **管理控制台**（`/login`）—— 基于角色的网页界面，用于管理用户、令牌与访问；种子 `admin` 首次登录强制改凭据。
- **用户管理** —— 创建用户（密码与令牌可自动生成或自定义）、设置/清除有效期、启用/禁用、删除，以及为用户重置密码（强制其下次登录改密并吊销其会话）。
- **自助服务** —— 普通用户可查看自身访问信息并自助修改密码。
- **实时系统健康** —— 管理面板展示 CPU、内存、磁盘、负载与运行时长，每隔数秒轮询（读取 `/proc`，无额外依赖）。
- **默认加固** —— 见 [安全](#安全)。

## 安全

- 密码使用 pbkdf2_sha256（12 万轮）+ 每用户盐哈希；常量时间比较；登录耗时已均衡以防用户名枚举。
- 会话令牌由服务端存储（`secrets.token_urlsafe`）。
- 控制面在 nginx 后由 gunicorn 运行；每个响应都设置安全头（CSP、HSTS、X-Frame-Options、X-Content-Type-Options、Referrer-Policy）并剥离 `Server` 头。
- 可选的 Cloudflare 源站闸门（nginx `geo` 基于真实对端地址）、关闭 nginx 默认欢迎页、`server_tokens off`。
- 按设备分配 Overlay IP 租约（杜绝地址碰撞）以及隧道源 IP 反欺骗。
- Windows 客户端使用 DPAPI 对访问令牌进行静态加密。

## 服务端安装（一条命令）

```bash
wget -qO- https://raw.githubusercontent.com/endlessdetour/Callsign/fast_iteration/deploy/install-server.sh | sudo CALLSIGN_BRANCH=fast_iteration bash
```

这条命令会自动完成：拉取/更新代码、读取/输入域名、自动申请 Let's Encrypt 证书（失败才回退自签）、启用证书自动续期、写入域名到 nginx 配置、生成 token、写入 systemd、启动服务。

可选参数：

- `CALLSIGN_BRANCH=fast_iteration` 安装指定分支
- `CALLSIGN_TRUST_CLOUDFLARE=1` 保留 nginx 的 Cloudflare 来源限制
- `CALLSIGN_REQUEST_SSL_CERT=0` 跳过 Let's Encrypt 申请并强制使用自签证书

默认行为：

- 交互式执行：安装器会询问域名，以及是否启用 Cloudflare-geo 限制（默认 `No`）
- 交互式执行：安装器会询问是否申请 Let's Encrypt SSL 证书（默认 `Yes`）
- 非交互执行：默认不启用 Cloudflare-geo，只有显式传入 `CALLSIGN_TRUST_CLOUDFLARE=1` 才启用
- 非交互执行：默认申请 Let's Encrypt，只有显式传入 `CALLSIGN_REQUEST_SSL_CERT=0` 才跳过申请

## 管理控制台

安装完成后，打开 `https://<你的域名>/login`。安装器会在结尾摘要中打印种子管理员凭据，并写入
`/etc/callsign/initial_admin_credentials.txt`（权限 `0600`，仅 root 可读）。

首次登录会要求你设置新的管理员用户名和密码，随后种子 `admin` 账号会被禁用。之后即可在控制台中
创建和管理用户、设置令牌有效期、重置密码，并查看实时系统健康。

## 客户端下载

- Windows ARM64：[点此下载](https://github.com/endlessdetour/Callsign/releases/latest/download/callsign-windows-arm64.zip)
- Windows x64：[点此下载](https://github.com/endlessdetour/Callsign/releases/latest/download/callsign-windows-x64.zip)
- Windows x86：[点此下载](https://github.com/endlessdetour/Callsign/releases/latest/download/callsign-windows-x86.zip)

说明：
- ARM64 链接是当前主要目标。
- 其他包你后续打好后按同样命名发布即可直接下载。

## 本地快速运行

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
./scripts/start-control.ps1
./scripts/start-tunnel.ps1
./scripts/start-client.ps1 -ControlUrl https://overlay.example.com
```

## 文档入口

- 架构说明：[docs/architecture.md](docs/architecture.md)
- Nginx 示例：[deploy/nginx.conf.example](deploy/nginx.conf.example)
- systemd 文件：[deploy/systemd](deploy/systemd)
- 一键安装脚本：[deploy/install-server.sh](deploy/install-server.sh)
