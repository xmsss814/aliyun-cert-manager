# aliyun-cert-manager

阿里云 SSL 证书自动管理工具。

支持：
- 检查本地证书有效期与域名匹配
- 复用 CAS 平台上已有的有效证书（避免重复申请）
- 自动申请新证书（免费 DV / 付费 DV / OV / EV），DNS 自动验证 + 轮询签发
- 灵活指定证书/私钥文件路径或目录
- 可选的 nginx reload 或自定义重载命令
- **Docker Compose 守护进程部署**（推荐）或 cron 定时
- 可选的**邮件通知**（QQ 邮箱 SMTP）：续期成功 / 失败时自动发信

> 密钥托管：**仅支持平台托管模式** —— 申请时不传 CSR/SAN，密钥对由阿里云生成并保管，签发后连私钥一并返回。
> 因此不支持自定义 SAN（`--san` / `CERT_SANS` 会被忽略并告警），详见下文与 FAQ。

---

## 目录结构

```
aliyun-cert-manager/
├── README.md
├── requirements.txt
├── .env.example
├── .gitignore
├── Dockerfile                 容器镜像构建
├── docker-compose.yml         守护进程部署编排
├── .dockerignore
├── scripts/
│   ├── cert_manager.py        主程序（含 --daemon 模式）
│   ├── install-cron.sh        安装 cron 定时续期（非 Docker 场景）
│   └── uninstall-cron.sh      卸载 cron 定时续期
```

---

## 部署方式一：Docker Compose（推荐）

镜像内置 `--daemon` 守护进程，周期性执行 `--renew`，无需在宿主机配置 cron。

### 1. 准备配置

```bash
cp .env.example .env
# 编辑 .env，填入 ALIBABA_CLOUD_ACCESS_KEY_ID / SECRET / CERT_DOMAIN
```

### 2. 启动

```bash
docker compose up -d --build
```

> 若构建时 `pip` 拉包失败（国内网络或公司代理拦截），可换镜像源后重试：
> ```bash
> PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple docker compose up -d --build
> ```

### 3. 查看日志 / 状态

```bash
docker compose logs -f cert-manager     # 实时日志
docker compose ps                       # 容器状态
docker compose restart                  # 立即触发一轮检查（容器重启即重新运行）
```

### 4. 证书文件

证书默认挂载到宿主机 `./certs/`，包含 `cert.pem` / `key.pem` / `fullchain.pem`，
其他容器可通过 volume 共享，或挂载到 nginx 宿主机目录。

### 配置项（通过 .env 注入）

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `ALIBABA_CLOUD_ACCESS_KEY_ID` | 阿里云 AccessKey ID（必填） | |
| `ALIBABA_CLOUD_ACCESS_KEY_SECRET` | 阿里云 AccessKey Secret（必填） | |
| `CERT_DOMAIN` | 证书主域名（必填） | |
| `CERT_TYPE` | 证书预设 `free-dv`/`dv`/`ov`/`ev` | `free-dv` |
| `ALIBABA_DNS_DOMAIN` | 阿里云 DNS 托管域名 | 同 `CERT_DOMAIN` |
| `RENEWAL_DAYS` | 提前多少天续期 | `30` |
| `INTERVAL_HOURS` | 守护进程检查间隔（小时） | `12` |
| `NO_RELOAD` | 1=禁用 reload（Docker 默认禁用） | `1` |
| `RELOAD_CMD` | 自定义 reload 命令 | |
| `NOTIFY_ENABLED` | 1=启用邮件通知 | `0` |
| `SMTP_HOST` / `SMTP_PORT` | 邮件服务器 | `smtp.qq.com` / `465` |
| `SMTP_SECURITY` | `ssl` / `starttls` / `plain` | `ssl` |
| `SMTP_USER` | 发件 QQ 邮箱地址 | |
| `SMTP_PASSWORD` | QQ 邮箱**授权码**（非登录密码） | |
| `NOTIFY_TO` | 收件人，逗号分隔 | 同 `SMTP_USER` |
| `NOTIFY_ON_NOOP` | 1=「无需续期」也发信 | `0` |

> 邮件通知的完整说明见 [邮件通知（QQ 邮箱）](#邮件通知qq-邮箱)。

### 在容器内 reload 其他服务

容器默认 `NO_RELOAD=1` 不执行 reload。如果想让续期后自动重启 nginx/blog 等服务，
有几种常见做法：

1. **共享 volume + 外部 watcher**：让目标容器 watch 证书目录变化，自行 reload。
2. **挂载 docker socket**（不推荐，权限放大）：
   ```yaml
   volumes:
     - /var/run/docker.sock:/var/run/docker.sock
   environment:
     NO_RELOAD: "0"
     RELOAD_CMD: "docker restart blog"
   ```
3. **API/webhook 触发**：`RELOAD_CMD` 设为 `curl -X POST http://blog:8080/reload`。

---

## 部署方式二：venv + cron

适合不便使用容器的服务器，由 cron 在宿主机周期性调用。

### 1. 安装依赖

```bash
cd ~/Desktop/aliyun-cert-manager
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 配置凭证

```bash
cp .env.example .env
# 编辑 .env，填入 ALIBABA_CLOUD_ACCESS_KEY_ID / SECRET / CERT_DOMAIN
```

### 3. 检查证书状态

```bash
python3 scripts/cert_manager.py --check
```

### 4. 自动续期

```bash
python3 scripts/cert_manager.py --renew
```

---

## 守护进程模式（手动 / systemd）

除 Docker 外，也可以直接以守护进程方式运行：

```bash
# 前台运行，每 6 小时检查一次
python3 scripts/cert_manager.py --daemon --interval-hours 6 \
    --domain example.com --cert-dir ./certs

# 立即执行一次后退出（调试用）
python3 scripts/cert_manager.py --daemon --run-once

# 跳过检查、强制重新签发一次（必须带 --run-once，否则拒绝启动）
python3 scripts/cert_manager.py --daemon --force-renew --run-once
```

或用 systemd 等进程管理工具托管：

```ini
# /etc/systemd/system/aliyun-cert-manager.service
[Service]
WorkingDirectory=/opt/aliyun-cert-manager
EnvironmentFile=/opt/aliyun-cert-manager/.env
ExecStart=/opt/aliyun-cert-manager/.venv/bin/python scripts/cert_manager.py --daemon
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

环境变量 `DAEMON=1`、`INTERVAL_HOURS=12` 可替代命令行参数。

> 模式优先级：命令行显式给出 `--check` / `--renew` / `--force-renew` 时以命令行为准，
> 即使环境变量 `DAEMON=1` 也不会被强行拉进守护进程（容器内执行一次性 `--check` 时很有用）。

---

## 命令行参数

| 参数 | 说明 | 默认值 |
| --- | --- | --- |
| `--check` | 检查本地与平台证书有效期 | (默认行为) |
| `--renew` | 三步流程：本地 → 平台 → 新建 | |
| `--force-renew` | 跳过检查，强制重新申请 | |
| `--daemon` | 守护进程，周期性执行 `--renew` | |
| `--interval-hours` | 守护进程间隔（小时） | `12` |
| `--run-once` | 守护进程模式下立即执行一次后退出 | |
| `--domain` | 证书主域名 | `CERT_DOMAIN` |
| `--san` | **不支持**：平台托管模式不传 CSR，SAN 由阿里云按主域名自动匹配；传入仅告警并忽略 | |
| `--dns-domain` | 阿里云 DNS 托管域名 | 同 `--domain` |
| `--cert-dir` | 证书存放目录 | `./certs` |
| `--cert-file` | 证书文件路径（覆盖 `--cert-dir/cert.pem`） | |
| `--key-file` | 私钥文件路径（覆盖 `--cert-dir/key.pem`） | |
| `--fullchain-file` | 完整链路径（覆盖 `--cert-dir/fullchain.pem`；显式传空字符串可关闭输出） | |
| `--no-fullchain` | 不写出 `fullchain.pem` | off |
| `--cert-type` | 证书预设：`free-dv`/`dv`/`ov`/`ev` | `free-dv` |
| `--product-code` | 阿里云 product_code（覆盖 `--cert-type`） | |
| `--renewal-days` | 提前多少天续期 | `30` |
| `--no-reload` | 续期后不执行 reload | 默认执行 `nginx -s reload` |
| `--reload-cmd` | 自定义 reload 命令 | |
| `--env-file` | 指定 .env 文件路径 | |
| `--daemon` | 守护进程模式 | off |
| `--interval-hours` | 守护进程间隔（小时） | `12` |
| `--run-once` | 守护进程模式下立即执行一次后退出 | |

> 优先级：命令行参数 > 环境变量 > .env > 默认值。

> 冲突规则：`--daemon` 配 `--force-renew` 会每轮强制重新签发，因此**必须同时带 `--run-once`**，
> 否则直接拒绝启动（exit 2）；`--daemon` 配 `--check` 时 `--check` 被忽略并告警。

---

## 使用示例

### 仅检查证书有效期

```bash
python3 scripts/cert_manager.py --check --domain example.com
```

### 指定证书目录

```bash
python3 scripts/cert_manager.py --renew \
    --domain example.com \
    --cert-dir /etc/nginx/certs
```

### 显式指定文件路径（用于自定义命名）

```bash
python3 scripts/cert_manager.py --renew \
    --domain example.com \
    --cert-file /etc/nginx/certs/example.com.pem \
    --key-file /etc/nginx/certs/example.com.key \
    --fullchain-file /etc/nginx/certs/example.com.fullchain.pem
```

### 申请付费 OV 证书

> 需先在阿里云 SSL 证书控制台购买对应资源包

```bash
python3 scripts/cert_manager.py --renew \
    --domain example.com \
    --cert-type ov
```

### 续期后通过 docker compose 重启容器

```bash
python3 scripts/cert_manager.py --renew \
    --domain example.com \
    --cert-dir ./certs \
    --reload-cmd "docker compose restart blog"
```

### 续期后不做任何 reload（外部脚本处理）

```bash
python3 scripts/cert_manager.py --renew \
    --domain example.com \
    --cert-dir ./certs \
    --no-reload
```

---

## 定时自动续期（cron，非 Docker 场景）

> Docker Compose 部署已内置守护进程，无需 cron。本节用于 venv/systemd 等场景。

提供 `install-cron.sh` / `uninstall-cron.sh`：

```bash
# 安装（默认每天 03:17 检查续期）
bash scripts/install-cron.sh

# 自定义 cron 表达式与参数
CRON_SCHEDULE="17 3 * * *" bash scripts/install-cron.sh \
    --domain example.com --cert-dir /etc/nginx/certs

# 查看已安装的 cron
crontab -l | grep cert_manager

# 卸载
bash scripts/uninstall-cron.sh
```

cron 调用项目内的 `cert_manager.py --renew`，日志写入 `~/aliyun-cert-manager.log`。

---

## 证书类型预设

| `--cert-type` | 阿里云 product_code | 说明 |
| --- | --- | --- |
| `free-dv` | `digicert-free-1-free` | 个人测试证书（免费版）3 个月 |
| `dv` | `symantec-dv-1-starter` | DV SSL（1 年） |
| `ov` | `symantec-ov-1-advanced` | OV SSL（1 年） |
| `ev` | `symantec-ev-1-premium` | EV SSL（1 年） |

> 阿里云可能调整 product_code；若失效，可通过 `--product-code xxx` 直接传最新值，无需等待本项目更新。

---

## 三步续期流程

1. **本地检查** — 读 `--cert-file` / `--key-file`，确认证书未过期、域名匹配、剩余天数 > `--renewal-days`。命中则跳过申请。
2. **平台检查** — 在 CAS 上查同域名已签发、未过期的订单，命中则下载并部署。
3. **新建** — 提交 DV/付费订单（平台托管模式：由阿里云生成并保管密钥对），自动添加 DNS 验证记录，轮询直至签发，写入证书 + 私钥并 reload。

> **密钥托管说明**：采用平台托管模式，私钥由阿里云生成与保管，签发时随证书一并返回。
> 好处是私钥丢失后仍可从平台重新获取（解决了旧版本地生成私钥丢失后只能重新签发的问题）；
> 代价是私钥经过第三方（阿里云）生成与存储。
>
> **本项目仅支持该模式**：没有"本地生成密钥对 / 自定义 CSR / 自定义 SAN"的开关，
> `--san` 与 `CERT_SANS` 会被忽略并告警（见 FAQ）。

---

## 邮件通知（QQ 邮箱）

可选功能，默认关闭；使用 Python 标准库 `smtplib`，无额外依赖。

### 1. 获取 QQ 邮箱授权码

登录 QQ 邮箱网页版 → **设置 → 账户** → 找到「POP3/IMAP/SMTP/Exchange/CardDAV/CalDAV服务」→
开启 **SMTP 服务**，按提示生成 **授权码**（16 位）。

> `SMTP_PASSWORD` 必须填这个**授权码**，不是 QQ 登录密码，也不是邮箱独立密码。

### 2. 配置

写入 `.env`（容器部署时 `docker-compose.yml` 已透传这些变量，无需改 compose 文件）：

```bash
NOTIFY_ENABLED=1
SMTP_HOST=smtp.qq.com                  # 默认值
SMTP_PORT=465                          # 默认值
SMTP_SECURITY=ssl                      # 465 用 ssl，587 用 starttls
SMTP_USER=you@qq.com                   # 发件邮箱
SMTP_PASSWORD=xxxxxxxxxxxxxxxx         # 授权码（16 位）
NOTIFY_TO=you@qq.com,ops@example.com   # 可省略，默认发给 SMTP_USER
NOTIFY_ON_NOOP=0                       # 1 = 无需续期也发信
```

非 Docker 场景（venv + cron）同样读取 `.env` 或环境变量，无需额外配置。

### 3. 发信时机

| 场景 | 是否发信 | 邮件标题 |
| --- | --- | --- |
| 新签发证书并部署成功 | ✅ | `[证书续期成功] example.com（新签发）` |
| 复用平台已有证书 | ✅ | `[证书续期成功] example.com（复用平台证书）` |
| 续期失败 / 异常 / 超时 / 保存失败 | ✅ | `[证书续期失败] example.com` |
| 本地证书仍有效，无需处理 | 仅当 `NOTIFY_ON_NOOP=1` | `[证书检查] example.com 无需续期` |

正文包含域名、结果、证书/私钥/完整链路径、证书过期时间与剩余天数，以及本轮完整运行日志。

> 邮件发送失败只打印 `WARN`，**不会影响证书续期本身**；`NOTIFY_ENABLED=1` 但缺少
> `SMTP_USER` / `SMTP_PASSWORD` / `NOTIFY_TO` 时会在启动日志中告警并跳过发信。

---

## FAQ

**Q: 一定要把域名 DNS 也托管在阿里云吗？**
A: 自动 DNS 验证需要阿里云 DNS。如果域名 DNS 不在阿里云，可手动添加验证记录（程序会打印需要的记录），或在阿里云把 DNS 解析转交给当前服务商。

**Q: AccessKey 需要哪些权限？**
A: `AliyunYundunCertFullAccess`（数字证书管理） + `AliyunDNSFullAccess`（云解析 DNS）。生产环境建议用 RAM 子账号 + 最小权限策略。

**Q: 私钥存在哪里？**
A: 私钥由阿里云生成并保管（平台托管模式），签发时随证书一并返回，同时写入本地 `key.pem`。之后平台仍可重新下载证书与私钥，本地文件丢失无需重新签发。

**Q: 为什么自定义 SAN（`CERT_SANS` / `--san`）不生效？**
A: 本工具**只使用平台托管模式**——申请时只提交 `domain`，不传 CSR、不传 SAN，密钥对由阿里云生成并保管，
因此 SAN 无法由本项目指定，只能由阿里云按主域名自动匹配（免费 DV 通常自动包含主域名 + `www.` 子域名）。
传入 `--san` / 设置 `CERT_SANS` 会被忽略并打印 `WARN`（不会静默丢弃），需要额外 SAN 请在阿里云控制台手动申请。
本地生成密钥对 + 自定义 CSR 的模式不在本项目支持范围内。

**Q: 怎么关闭 `fullchain.pem` 输出？**
A: 用 `--no-fullchain`，或把环境变量显式设为空（`FULLCHAIN_FILE=` 后不写任何字符，Docker Compose 里写 `FULLCHAIN_FILE: ""`）。
默认仍会写 `<cert-dir>/fullchain.pem`。

**Q: 续期失败会通知我吗？**
A: 可以。设置 `NOTIFY_ENABLED=1` 并配好 `SMTP_USER` / `SMTP_PASSWORD`（QQ 邮箱授权码）/ `NOTIFY_TO` 后，
续期成功、失败都会发邮件，详见 [邮件通知（QQ 邮箱）](#邮件通知qq-邮箱)。
未开启通知时仅写日志到 stdout / cron 日志文件，可配合 `runitor` / `healthchecks.io` 之类的工具实现告警。

---

## License

MIT
