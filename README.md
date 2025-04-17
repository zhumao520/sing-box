# 介绍

最好用的 sing-box 一键安装脚本 & 管理脚本

## 安装指南

### 主脚本安装
使用以下命令安装主脚本：

```bash
wget -N --no-check-certificate https://github.com/zhumao520/sing-box/raw/main/install.sh && bash install.sh
```

这将安装sing-box并设置基本配置。安装完成后，您可以使用`sing-box`命令管理您的配置。

### WARP出站代理功能安装
如果您希望所有流量通过Cloudflare WARP代理出站，请使用以下命令：

```bash
wget -N --no-check-certificate https://github.com/zhumao520/sing-box/raw/main/docker-warp.sh && bash docker-warp.sh
```

# 特点

- 快速安装
- 无敌好用
- 零学习成本
- 自动化 TLS
- 简化所有流程
- 兼容 sing-box 命令
- 强大的快捷参数
- 支持所有常用协议
- 一键添加 VLESS-REALITY (默认)
- 一键添加 TUIC
- 一键添加 Trojan
- 一键添加 Hysteria2
- 一键添加 Shadowsocks 2022
- 一键添加 VMess-(TCP/HTTP/QUIC)
- 一键添加 VMess-(WS/H2/HTTPUpgrade)-TLS
- 一键添加 VLESS-(WS/H2/HTTPUpgrade)-TLS
- 一键添加 Trojan-(WS/H2/HTTPUpgrade)-TLS
- 一键启用 BBR
- 一键更改伪装网站
- 一键更改 (端口/UUID/密码/域名/路径/加密方式/SNI/等...)
- 还有更多...

# 设计理念

设计理念为：**高效率，超快速，极易用**

脚本基于作者的自身使用需求，以 **多配置同时运行** 为核心设计

并且专门优化了，添加、更改、查看、删除、这四项常用功能

你只需要一条命令即可完成 添加、更改、查看、删除、等操作

例如，添加一个配置仅需不到 1 秒！瞬间完成添加！其他操作亦是如此！

脚本的参数非常高效率并且超级易用，请掌握参数的使用

# 文档

安装及使用：https://github.com/zhumao520/sing-box

# 帮助

使用：`sing-box help`

## WARP 代理出站功能

所有协议的出站流量都会经过 Cloudflare WARP 代理（127.0.0.1:1080）。此功能由`docker-warp.sh`脚本实现，它会：

1. 安装 Docker 和 WARP 容器
2. 修改所有协议配置文件，使其出站流量经过 WARP 代理
3. 更新主配置文件，添加 WARP 代理出站
4. 更新路由规则，确保所有入站流量都通过 WARP 代理出站

### 使用方法

运行以下命令：

```bash
wget -N --no-check-certificate https://github.com/zhumao520/sing-box/raw/main/docker-warp.sh && bash docker-warp.sh
```

脚本会自动完成所有配置。运行后，所有通过sing-box的流量都将经过Cloudflare WARP代理出站。

### 功能详情

- **支持的协议**：脚本会自动修改所有协议配置文件，包括Hysteria2、VLESS、Trojan、TUIC、VMess和Shadowsocks
- **自动配置**：安装Docker、WARP客户端容器并配置所有出站流量经过WARP
- **路由规则**：自动设置入站流量全部经过WARP出站
- **保留原始配置**：保留每个协议的原始入站配置，只修改出站部分
- **备份机制**：修改配置前会自动备份原始配置文件

### 配置文件位置

- 各协议配置文件：`/etc/sing-box/conf/*.json`
- 主配置文件：`/etc/sing-box/config.json`
- WARP数据目录：`/mnt/warp/data`

### 故障排除

如果遇到问题，请检查：

1. WARP容器是否正常运行：`docker ps -a | grep warp`
2. SOCKS代理是否可访问：`curl --socks5 127.0.0.1:1080 http://ip.sb`
3. Sing-box服务状态：`systemctl status sing-box`
Usage: sing-box [options]... [args]...

基本:
   v, version                                      显示当前版本
   ip                                              返回当前主机的 IP
   pbk                                             同等于 sing-box generate reality-keypair
   get-port                                        返回一个可用的端口
   ss2022                                          返回一个可用于 Shadowsocks 2022 的密码

一般:
   a, add [protocol] [args... | auto]              添加配置
   c, change [name] [option] [args... | auto]      更改配置
   d, del [name]                                   删除配置**
   i, info [name]                                  查看配置
   qr [name]                                       二维码信息
   url [name]                                      URL 信息
   log                                             查看日志
更改:
   full [name] [...]                               更改多个参数
   id [name] [uuid | auto]                         更改 UUID
   host [name] [domain]                            更改域名
   port [name] [port | auto]                       更改端口
   path [name] [path | auto]                       更改路径
   passwd [name] [password | auto]                 更改密码
   key [name] [Private key | atuo] [Public key]    更改密钥
   method [name] [method | auto]                   更改加密方式
   sni [name] [ ip | domain]                       更改 serverName
   new [name] [...]                                更改协议
   web [name] [domain]                             更改伪装网站

进阶:
   dns [...]                                       设置 DNS
   dd, ddel [name...]                              删除多个配置**
   fix [name]                                      修复一个配置
   fix-all                                         修复全部配置
   fix-caddyfile                                   修复 Caddyfile
   fix-config.json                                 修复 config.json
   import                                          导入 sing-box/v2ray 脚本配置

管理:
   un, uninstall                                   卸载
   u, update [core | sh | caddy] [ver]             更新
   U, update.sh                                    更新脚本
   s, status                                       运行状态
   start, stop, restart [caddy]                    启动, 停止, 重启
   t, test                                         测试运行
   reinstall                                       重装脚本

测试:
   debug [name]                                    显示一些 debug 信息, 仅供参考
   gen [...]                                       同等于 add, 但只显示 JSON 内容, 不创建文件, 测试使用
   no-auto-tls [...]                               同等于 add, 但禁止自动配置 TLS, 可用于 *TLS 相关协议
其他:
   bbr                                             启用 BBR, 如果支持
   bin [...]                                       运行 sing-box 命令, 例如: sing-box bin help
   [...] [...]                                     兼容绝大多数的 sing-box 命令, 例如: sing-box generate uuid
   h, help                                         显示此帮助界面
如有其他问题，请在GitHub仓库提交issue。
