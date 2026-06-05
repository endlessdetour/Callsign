# Callsign

[English](README.md) | 简体中文

Callsign 是一个轻量级 Overlay 网络原型。

## 服务端安装（一条命令）

```bash
wget -qO- https://raw.githubusercontent.com/endlessdetour/Callsign/main/deploy/install-server.sh | sudo CALLSIGN_DOMAIN=cloud.example.com bash
```

这条命令会自动完成：拉取/更新代码、读取/输入域名、写入域名到 nginx 配置、生成 token、写入 systemd、启动服务。

可选参数：

- `CALLSIGN_BRANCH=fast_iteration` 安装指定分支
- `CALLSIGN_TRUST_CLOUDFLARE=1` 保留 nginx 的 Cloudflare 来源限制

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
