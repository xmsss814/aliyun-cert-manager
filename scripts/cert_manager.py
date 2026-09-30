#!/usr/bin/env python3
"""
阿里云 SSL 证书自动管理工具（独立版本）

功能:
  1. 检查本地证书有效期
  2. 检查 CAS 平台是否已有有效证书（已签发、未过期）
  3. 本地和平台均无有效证书时，自动申请阿里云 DV / OV / EV 证书
     （平台托管模式：不传 CSR，由阿里云生成并保管密钥对，签发后连私钥一并返回，
      旧证书私钥丢失时可直接从平台重新下载）
  4. 自动完成 DNS 验证（需阿里云 DNS 服务）
  5. 下载证书到指定目录或文件路径
  6. 守护进程模式 (--daemon)，定时执行续期检查（用于容器化部署）
  7. 可选邮件通知（QQ 邮箱 SMTP）：续期成功 / 失败时发信，默认关闭

使用方式:
  python3 cert_manager.py --check                 # 检查本地和平台证书状态
  python3 cert_manager.py --renew                 # 三步检查，需要时自动续期
  python3 cert_manager.py --force-renew           # 跳过检查，强制重新申请
  python3 cert_manager.py --renew --no-reload     # 续期后不重载 nginx
  python3 cert_manager.py --daemon                # 守护进程，默认每 12 小时执行一次 --renew
  python3 cert_manager.py --daemon --interval-hours 6
  python3 cert_manager.py --renew \\
      --domain app.example.com \\
      --cert-dir /etc/nginx/certs \\
      --cert-type free-dv

配置优先级: 命令行参数 > 环境变量 > .env 文件 > 默认值

环境变量:
  ALIBABA_CLOUD_ACCESS_KEY_ID      阿里云 AccessKey ID (必填)
  ALIBABA_CLOUD_ACCESS_KEY_SECRET  阿里云 AccessKey Secret (必填)
  CERT_DOMAIN                      证书域名 (必填)
  CERT_DIR                         证书存放目录 (默认 ./certs)
  CERT_FILE                        证书文件路径 (覆盖 CERT_DIR/cert.pem)
  KEY_FILE                         私钥文件路径 (覆盖 CERT_DIR/key.pem)
  FULLCHAIN_FILE                   完整链证书路径 (覆盖 CERT_DIR/fullchain.pem)；
                                   显式设为空字符串可关闭 fullchain 输出
  CERT_TYPE                        证书类型预设 (free-dv/dv/ov/ev)
  PRODUCT_CODE                     阿里云 product_code (覆盖 CERT_TYPE)
  RENEWAL_DAYS                     提前多少天续期 (默认 30)
  CERT_SANS                        不支持：本工具仅使用平台托管模式（不传 CSR），
                                   SAN 由阿里云按主域名自动匹配，此项会被忽略并告警
  ALIBABA_DNS_DOMAIN               阿里云 DNS 管理的域名 (默认同 CERT_DOMAIN)
  RELOAD_CMD                       自定义重载命令 (如 "docker compose restart blog")
  NO_RELOAD                        设为 1 禁用自动 reload
  DAEMON                           设为 1 启用守护进程模式 (命令行指定模式时以命令行为准)
  INTERVAL_HOURS                   守护进程检查间隔小时数 (默认 12)

  NOTIFY_ENABLED                   设为 1 启用邮件通知 (默认关闭)
  SMTP_HOST / SMTP_PORT            邮件服务器 (默认 smtp.qq.com:465)
  SMTP_SECURITY                    ssl / starttls / plain (默认 ssl，对应 465 端口)
  SMTP_USER                        SMTP 登录名，即 QQ 邮箱地址
  SMTP_PASSWORD                    SMTP 密码：QQ 邮箱「授权码」(非 QQ 登录密码)
  NOTIFY_FROM                      发件人 (默认同 SMTP_USER)
  NOTIFY_TO                        收件人，逗号分隔 (默认同 SMTP_USER)
  NOTIFY_ON_NOOP                   设为 1 时"无需续期"也发通知 (默认 0，只在续期/失败时发信)
"""

import os
import sys
import time
import argparse
import datetime
import signal
import smtplib
import subprocess
from email.message import EmailMessage
from pathlib import Path
from typing import List, Optional, Tuple

# ---------- 密钥托管模式 ----------
#
# 本工具**只支持平台托管模式**：申请时不传 CSR、不传 SAN，密钥对由阿里云生成并保管，
# 签发后连私钥一并返回（因此本地私钥丢失无需重新签发）。
#
# 与之相对的「本地生成密钥对 + 自定义 CSR/SAN」模式不在支持范围内，故：
#   - create_certificate_order() 不接收 CSR / SAN 参数
#   - --san / CERT_SANS 仅作兼容占位，传入会被忽略并告警（见 parse_args）
# 若将来要新增 CSR 模式，需在此处扩展 KEY_MODE 并同步 README。

KEY_MODE = "platform"
KEY_MODE_LABEL = "平台托管（阿里云生成并保管私钥，不传 CSR/SAN）"

# ---------- defaults & presets ----------

DEFAULT_RENEWAL_DAYS = 30
DEFAULT_REGION = "cn-hangzhou"
DEFAULT_CERT_DIR = "./certs"
DEFAULT_INTERVAL_HOURS = 12

# 证书类型预设 → 阿里云 product_code
# 注意：product_code 可能随阿里云调整而变化，付费类型需先在阿里云购买对应资源包
CERT_TYPE_PRESETS = {
    "free-dv": "digicert-free-1-free",      # 个人测试证书（免费版）3个月
    "dv":      "symantec-dv-1-starter",      # DV SSL（1年）
    "ov":      "symantec-ov-1-advanced",     # OV SSL（1年）
    "ev":      "symantec-ev-1-premium",      # EV SSL（1年）
}

# ---------- logging ----------

# 本轮运行的日志缓冲，用于失败/成功通知邮件正文（只保留最近 MAX_RUN_LOG 行）
_RUN_LOG: List[str] = []
MAX_RUN_LOG = 300


def log(msg: str) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    _RUN_LOG.append(line)
    if len(_RUN_LOG) > MAX_RUN_LOG:
        del _RUN_LOG[:-MAX_RUN_LOG]


def reset_run_log() -> None:
    """每轮续期开始前调用，保证通知邮件只包含本轮日志"""
    _RUN_LOG.clear()


# ---------- config container ----------

class Config:
    """运行期配置，由 parse_args() 填充"""
    domain: str = ""
    dns_domain: str = ""
    cert_dir: Path
    cert_file: Path
    key_file: Path
    fullchain_file: Optional[Path] = None   # None = 关闭 fullchain 输出
    renewal_days: int = DEFAULT_RENEWAL_DAYS
    product_code: str = CERT_TYPE_PRESETS["free-dv"]
    no_reload: bool = False
    reload_cmd: Optional[str] = None
    daemon: bool = False
    interval_hours: float = DEFAULT_INTERVAL_HOURS
    run_once: bool = False
    force_renew: bool = False
    renew: bool = False
    check: bool = False
    # 本轮实际动作：skip(无需续期) / platform(复用平台证书) / new(新签发) / failed
    last_action: str = ""
    last_error: str = ""


# ---------- sdk imports (lazy) ----------
#
# SDK 在首次调用阿里云 API 时才加载，方便用户在没有装齐依赖时也能查看 --help。

CasClient = None
CasModels = None
DnsClient = None
DnsModels = None
OpenApiModels = None

_SDK_LOADED = False


def _load_sdk() -> None:
    """首次调用阿里云 API 时加载 SDK 模块"""
    global _SDK_LOADED, CasClient, CasModels, DnsClient, DnsModels, OpenApiModels
    if _SDK_LOADED:
        return
    try:
        from alibabacloud_cas20200407.client import Client as CasClient_
        from alibabacloud_cas20200407 import models as cas_models_
        from alibabacloud_alidns20150109.client import Client as DnsClient_
        from alibabacloud_alidns20150109 import models as dns_models_
        from alibabacloud_tea_openapi import models as open_api_models_
    except ImportError:
        log("缺少阿里云 SDK，请运行: pip install -r requirements.txt")
        sys.exit(1)
    CasClient = CasClient_
    CasModels = cas_models_
    DnsClient = DnsClient_
    DnsModels = dns_models_
    OpenApiModels = open_api_models_
    _SDK_LOADED = True


from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend


# ---------- Alibaba Cloud clients ----------

def _create_cas_client():
    _load_sdk()
    config = OpenApiModels.Config(
        access_key_id=os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"],
        access_key_secret=os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"],
        region_id=DEFAULT_REGION,
    )
    config.endpoint = "cas.aliyuncs.com"
    return CasClient(config)


def _create_dns_client():
    _load_sdk()
    config = OpenApiModels.Config(
        access_key_id=os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"],
        access_key_secret=os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"],
        region_id=DEFAULT_REGION,
    )
    config.endpoint = "alidns.aliyuncs.com"
    return DnsClient(config)


# ---------- certificate parsing ----------

def parse_cert_expiry(cert_path: Path) -> Optional[datetime.datetime]:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes(), default_backend())
        return cert.not_valid_after_utc
    except Exception as e:
        log(f"无法解析证书 {cert_path}: {e}")
        return None


def days_until_expiry(expiry: datetime.datetime) -> int:
    return (expiry - datetime.datetime.now(datetime.timezone.utc)).days


# ---------- domain resolution ----------

def resolve_cert_domains(primary_domain: str) -> list:
    """解析目标域名列表（仅用于日志展示与核对）

    平台托管模式不传 CSR/SAN，实际 SAN 由阿里云按 domain 自动匹配
    （免费 DV 通常自动包含主域名 + www. 子域名），因此这里只列出主域名与 www 形式。
    """
    domains = [primary_domain]
    if primary_domain and not primary_domain.startswith("www."):
        www_domain = f"www.{primary_domain}"
        if www_domain not in domains:
            domains.append(www_domain)
    return domains


# ---------- CAS API ----------

def create_certificate_order(domain: str, product_code: str) -> str:
    """申请证书，返回 OrderId

    平台托管模式：**不传 CSR、不传 SAN**，密钥对由阿里云生成并保管，
    签发时随证书一并返回（私有化 CSR 模式不在本项目支持范围内）。
    """
    client = _create_cas_client()
    req = CasModels.CreateCertificateForPackageRequestRequest(
        domain=domain,
        validate_type="DNS",
        product_code=product_code,
        username="",
        phone="",
        email="",
    )
    resp = client.create_certificate_for_package_request(req)
    order_id = resp.body.order_id
    log(f"证书申请已提交，OrderId: {order_id}，product_code: {product_code}")
    return str(order_id)


def get_certificate_state(order_id: str) -> dict:
    client = _create_cas_client()
    resp = client.describe_certificate_state(
        CasModels.DescribeCertificateStateRequest(order_id=int(order_id))
    )
    b = resp.body
    return {
        "type": b.type,
        "certificate": b.certificate or "",
        "private_key": b.private_key or "",
        "record_type": b.record_type or "",
        "record_value": b.record_value or "",
        "record_domain": b.record_domain or "",
        "validate_type": b.validate_type or "",
    }


def cancel_certificate_order(order_id: str) -> None:
    """取消未签发的订单（DeleteCertificateRequest 只能删已签发证书，删不了 payed 状态订单）"""
    try:
        client = _create_cas_client()
        client.cancel_certificate_for_package_request(
            CasModels.CancelCertificateForPackageRequestRequest(order_id=int(order_id))
        )
        log(f"已取消订单 {order_id}")
    except Exception as e:
        log(f"取消订单 {order_id} 失败 (可忽略): {e}")


def delete_certificate_order(order_id: str) -> None:
    try:
        client = _create_cas_client()
        client.delete_certificate_request(
            CasModels.DeleteCertificateRequestRequest(order_id=int(order_id))
        )
        log(f"已删除订单 {order_id}")
    except Exception as e:
        log(f"删除订单 {order_id} 失败: {e}")


def list_platform_certificates(keyword: str = "", status: str = "ISSUED",
                                order_type: str = "CERT") -> list:
    client = _create_cas_client()
    req = CasModels.ListUserCertificateOrderRequest(
        keyword=keyword, status=status, order_type=order_type, show_size=50,
    )
    resp = client.list_user_certificate_order(req)
    return resp.body.certificate_order_list or []


def get_certificate_detail(cert_id: int) -> Optional[dict]:
    try:
        client = _create_cas_client()
        resp = client.get_user_certificate_detail(
            CasModels.GetUserCertificateDetailRequest(cert_id=cert_id, cert_filter=False)
        )
        b = resp.body
        return {
            "cert": b.cert or "",
            "key": b.key or "",
            "domain": b.common or "",
            "sans": b.sans or "",
            "end_date": b.end_date or "",
            "expired": b.expired,
            "cert_id": b.id,
        }
    except Exception as e:
        log(f"获取证书详情失败 (cert_id={cert_id}): {e}")
        return None


def _domain_matches(target: str, cert_common: str, cert_sans: str) -> bool:
    if target == cert_common:
        return True
    if cert_sans and target in [s.strip() for s in cert_sans.split(",")]:
        return True
    return False


def find_valid_platform_cert(domain: str) -> Optional[int]:
    """查找平台上有效且带私钥的证书；返回 cert_id，找不到返回 None"""
    log(f"查询平台上 {domain} 的已有证书 ...")
    orders = list_platform_certificates(keyword=domain, status="ISSUED", order_type="CERT")
    if not orders:
        log("平台上未找到已签发的证书")
        return None

    now = datetime.datetime.now(datetime.timezone.utc)
    no_key_candidates = []
    for item in orders:
        end_date_str = getattr(item, "end_date", "") or ""
        cert_common = getattr(item, "common_name", "") or ""
        cert_sans = getattr(item, "sans", "") or ""
        cert_id = getattr(item, "certificate_id", None) or getattr(item, "cert_id", None)
        if not end_date_str or not cert_id:
            continue
        if not _domain_matches(domain, cert_common, cert_sans):
            continue
        try:
            end_date = datetime.datetime.strptime(end_date_str, "%Y-%m-%d").replace(
                tzinfo=datetime.timezone.utc
            )
        except ValueError:
            continue
        remaining = (end_date - now).days
        if remaining <= 0:
            continue

        # 只有能连私钥一起下载的证书才可复用
        detail = get_certificate_detail(int(cert_id))
        if detail and detail.get("cert") and detail.get("key"):
            log(f"平台找到有效证书(含私钥): domain={cert_common}, cert_id={cert_id}, "
                f"过期={end_date_str}, 剩余={remaining}天")
            return int(cert_id)
        no_key_candidates.append(f"{cert_id}(过期={end_date_str}, 剩余={remaining}天, 无私钥)")

    if no_key_candidates:
        log(f"平台证书均无私钥: {', '.join(no_key_candidates)}")
    log("平台上未找到匹配且含私钥的未过期证书")
    return None


def download_platform_cert(cert_id: int) -> Optional[Tuple[str, str]]:
    detail = get_certificate_detail(cert_id)
    if not detail:
        return None
    cert_pem = detail.get("cert", "")
    key_pem = detail.get("key", "")
    if not cert_pem:
        log(f"平台证书 {cert_id} 无证书内容")
        return None
    return cert_pem, key_pem


# ---------- DNS API ----------

def resolve_dns_zone(record_domain: str, candidates: list) -> Optional[str]:
    """从候选域名中找出 record_domain 实际所属的 DNS 托管域（取最长后缀匹配）"""
    rd = record_domain.rstrip(".")
    best = None
    for cand in candidates:
        c = cand.rstrip(".")
        if rd == c or rd.endswith(f".{c}"):
            if best is None or len(c) > len(best):
                best = c
    return best


def _record_field(record, *names, default=""):
    """兼容不同 SDK 版本的字段命名

    alibabacloud-alidns20150109 4.x 中 DNS 解析记录的类型字段是 `type`，
    3.x 里是 `type_`（旧版为避免与内置名冲突的写法）。requirements 允许 >=3.0.0，
    故这里按顺序取第一个存在的字段，避免再次出现 AttributeError。
    """
    for n in names:
        v = getattr(record, n, None)
        if v is not None:
            return v
    return default


def _get_domain_record(domain: str, rr: str, type_: str) -> Optional[dict]:
    client = _create_dns_client()
    resp = client.describe_domain_records(
        DnsModels.DescribeDomainRecordsRequest(
            domain_name=domain, rrkey_word=rr, type=type_,
        )
    )
    records = resp.body.domain_records.record if resp.body.domain_records else []
    for r in records or []:
        if _record_field(r, "rr") == rr:
            return {
                "record_id": _record_field(r, "record_id"),
                "rr": _record_field(r, "rr"),
                "type": _record_field(r, "type", "type_"),
                "value": _record_field(r, "value"),
            }
    return None


def upsert_dns_record(domain: str, rr: str, type_: str, value: str) -> None:
    existing = _get_domain_record(domain, rr, type_)
    if existing:
        if existing["value"] == value:
            log(f"DNS 记录已存在: {rr}.{domain} {type_} {value}")
            return
        log(f"更新 DNS 记录: {rr}.{domain} {type_} {value}")
        client = _create_dns_client()
        client.update_domain_record(DnsModels.UpdateDomainRecordRequest(
            record_id=existing["record_id"], rr=rr, type=type_, value=value,
        ))
    else:
        log(f"新增 DNS 记录: {rr}.{domain} {type_} {value}")
        client = _create_dns_client()
        client.add_domain_record(DnsModels.AddDomainRecordRequest(
            domain_name=domain, rr=rr, type=type_, value=value,
        ))


# ---------- issuance wait ----------

def wait_for_issuance(order_id: str, dns_candidates: list,
                      timeout: int = 600, interval: int = 10) -> Optional[Tuple[str, str]]:
    """轮询直到证书签发完成，返回 (证书 PEM, 私钥 PEM)

    dns_candidates: DNS 托管域名候选列表（按 record_domain 后缀自动匹配，
                    解决 ALIBABA_DNS_DOMAIN 配错成父域名/子域名的问题）
    dns_added: 函数内维护，只在首次添加后长等待，之后改短轮询（幂等不重复添加）
    """
    deadline = time.time() + timeout
    log(f"等待证书签发 (最长 {timeout}s) ...")
    dns_added = False

    while time.time() < deadline:
        state = get_certificate_state(order_id)
        status = (state["type"] or "").lower()

        if status == "certificate":
            cert = state.get("certificate", "")
            key = state.get("private_key", "")
            if not cert:
                log("状态为 certificate 但未返回证书内容")
                return None
            if not key:
                log("状态为 certificate 但未返回私钥")
                return None
            log("证书已签发")
            return cert, key

        if status in ("verify_fail", "failed"):
            log(f"证书申请失败: type={status}")
            return None

        if status in ("payed", "domain_verify", "process"):
            record_type = state.get("record_type", "")
            record_value = state.get("record_value", "")
            record_domain = state.get("record_domain", "")
            if record_type and record_value and record_domain:
                log(f"需要 DNS 验证: 类型={record_type}, 记录值={record_value}, 记录域名={record_domain}")
                zone = resolve_dns_zone(record_domain, dns_candidates)
                if not zone:
                    log(f"WARN: {record_domain} 不匹配任何 DNS 托管域 {dns_candidates}，"
                        f"跳过自动 DNS 验证（域名在阿里云 DNS 托管时平台会自动验证）")
                else:
                    rr = record_domain.rstrip(".")[: -(len(zone) + 1)] if \
                        record_domain.rstrip(".") != zone else ""
                    if not rr:
                        log(f"WARN: 无法从 {record_domain} 提取 RR 前缀，跳过自动 DNS 验证")
                    else:
                        upsert_dns_record(zone, rr, record_type, record_value)
                        if not dns_added:
                            dns_added = True
                            log("DNS 记录已添加，等待验证生效 ...")
                            time.sleep(60)
                            continue
            else:
                log(f"订单状态: {status}，等待进入验证阶段 ...")
        else:
            log(f"订单状态: {status}，继续等待 ...")

        time.sleep(interval)

    log(f"超时: 证书在 {timeout}s 内未签发")
    return None


# ---------- save & deploy ----------

def save_and_apply_cert(cfg: Config, cert_pem: str, key_pem: str) -> bool:
    """保存证书和私钥到指定路径，并按需触发 reload"""
    cfg.cert_file.parent.mkdir(parents=True, exist_ok=True)
    cfg.key_file.parent.mkdir(parents=True, exist_ok=True)
    if cfg.fullchain_file:
        cfg.fullchain_file.parent.mkdir(parents=True, exist_ok=True)

    # 备份旧文件
    targets = [cfg.cert_file, cfg.key_file]
    if cfg.fullchain_file:
        targets.append(cfg.fullchain_file)
    for f in targets:
        if f.exists():
            backup = Path(str(f) + f".bak.{int(time.time())}")
            f.rename(backup)
            log(f"旧文件备份到 {backup}")

    cfg.cert_file.write_text(cert_pem)
    cfg.key_file.write_text(key_pem)
    if cfg.fullchain_file:
        cfg.fullchain_file.write_text(cert_pem)

    cfg.key_file.chmod(0o600)
    for f in [cfg.cert_file] + ([cfg.fullchain_file] if cfg.fullchain_file else []):
        f.chmod(0o644)

    log(f"证书已保存: cert={cfg.cert_file}, key={cfg.key_file}"
        + (f", fullchain={cfg.fullchain_file}" if cfg.fullchain_file else ""))

    if cfg.no_reload:
        log("--no-reload 已设置，跳过 reload")
        return True

    reload_cmd = cfg.reload_cmd or "nginx -s reload"
    log(f"执行 reload: {reload_cmd}")
    try:
        subprocess.run(reload_cmd, shell=True, check=True, timeout=30)
        log("reload 完成")
    except subprocess.CalledProcessError as e:
        log(f"reload 失败 (exit={e.returncode}): {e}")
    except subprocess.TimeoutExpired:
        log("reload 超时")
    except FileNotFoundError as e:
        log(f"reload 命令未找到: {e}")
    return True


def check_local_cert_valid(cfg: Config) -> bool:
    """检查本地是否有目标域名的有效证书"""
    if not cfg.cert_file.exists() or not cfg.key_file.exists():
        log(f"本地证书文件不存在: {cfg.cert_file} 或 {cfg.key_file}")
        return False

    expiry = parse_cert_expiry(cfg.cert_file)
    if expiry is None:
        log("无法解析本地证书")
        return False

    remaining = days_until_expiry(expiry)
    log(f"本地证书: 域名={cfg.domain}, 过期时间={expiry.strftime('%Y-%m-%d %H:%M:%S UTC')}, "
        f"剩余={remaining}天 (续期阈值={cfg.renewal_days}天)")

    if remaining <= cfg.renewal_days:
        log(f"本地证书即将过期（剩余 {remaining} 天 ≤ 阈值 {cfg.renewal_days} 天），需要续期")
        return False

    # 检查证书中的域名是否匹配
    try:
        cert = x509.load_pem_x509_certificate(cfg.cert_file.read_bytes(), default_backend())
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cert_cn = cn[0].value if cn else ""
        if cfg.domain not in (cert_cn, "") and cfg.domain not in str(cert_cn):
            log(f"本地证书域名不匹配: 证书CN={cert_cn}, 期望={cfg.domain}")
            return False
    except Exception:
        pass

    log("本地证书有效，无需续期")
    return True


# ---------- renewal flows ----------

def _set_action(cfg: Config, action: str, error: str = "") -> None:
    """记录本轮实际动作，供通知邮件判断是否需要发信"""
    cfg.last_action = action
    cfg.last_error = error


def do_renew(cfg: Config) -> bool:
    """三步续期：本地 → 平台 → 新建"""
    if not cfg.domain:
        log("错误: 未指定 --domain / CERT_DOMAIN")
        _set_action(cfg, "failed", "未指定域名")
        return False

    log(f"密钥托管模式: {KEY_MODE_LABEL}")
    log(f"目标域名列表: {resolve_cert_domains(cfg.domain)}")

    log("===== 第 1 步：检查本地证书 =====")
    if check_local_cert_valid(cfg):
        _set_action(cfg, "skip")
        return True

    log("===== 第 2 步：检查平台已有证书 =====")
    platform_cert_id = find_valid_platform_cert(cfg.domain)
    if platform_cert_id:
        cert_key = download_platform_cert(platform_cert_id)
        if cert_key:
            cert_pem, key_pem = cert_key
            log("平台证书含私钥，直接使用")
            ok = save_and_apply_cert(cfg, cert_pem, key_pem)
            _set_action(cfg, "platform" if ok else "failed",
                        "" if ok else "平台证书保存/部署失败")
            return ok
        log("下载平台证书失败，需要重新申请")

    log("===== 第 3 步：申请新证书 =====")
    return _apply_new_cert(cfg)


def do_renew_force(cfg: Config) -> bool:
    """强制重新申请证书（跳过本地和平台检查）"""
    if not cfg.domain:
        log("错误: 未指定 --domain / CERT_DOMAIN")
        _set_action(cfg, "failed", "未指定域名")
        return False

    log(f"密钥托管模式: {KEY_MODE_LABEL}")
    log(f"目标域名列表: {resolve_cert_domains(cfg.domain)}")
    log("强制重新申请模式: 跳过本地和平台检查")
    return _apply_new_cert(cfg)


def _dns_candidates(cfg: Config) -> list:
    """DNS 托管域候选列表：显式配置 + 主域名及其各级父域，按后缀自动匹配"""
    candidates = []
    for c in (cfg.dns_domain, cfg.domain):
        if c and c not in candidates:
            candidates.append(c)
            parts = c.split(".")
            for i in range(2, len(parts)):
                parent = ".".join(parts[-i:])
                if parent not in candidates:
                    candidates.append(parent)
    return candidates


def _cleanup_failed_order(order_id: str) -> None:
    """失败订单清理：先取消（payed 状态），取消不了再尝试删除"""
    cancel_certificate_order(order_id)
    delete_certificate_order(order_id)


def _apply_new_cert(cfg: Config) -> bool:
    old_cert_exists = cfg.cert_file.exists() and cfg.key_file.exists()

    log(f"申请方式: {KEY_MODE_LABEL}")

    try:
        order_id = create_certificate_order(cfg.domain, cfg.product_code)
    except Exception as e:
        log(f"创建证书订单失败: {e}")
        _set_action(cfg, "failed", f"创建证书订单失败: {e}")
        return False

    try:
        result = wait_for_issuance(order_id, _dns_candidates(cfg))
    except KeyboardInterrupt:
        log("用户中断，清理订单 ...")
        _cleanup_failed_order(order_id)
        _set_action(cfg, "failed", "用户中断")
        return False
    except Exception as e:
        log(f"等待签发时出错: {e}")
        # 警告：域名托管在阿里云 DNS 时，残留订单仍可能被平台自动验证并签发
        _cleanup_failed_order(order_id)
        _set_action(cfg, "failed", f"等待签发出错: {e}")
        return False

    if not result:
        log("未能获取证书，清理订单 ...")
        _cleanup_failed_order(order_id)
        _set_action(cfg, "failed", "订单未在超时时间内签发")
        return False

    cert_pem, key_pem = result
    success = save_and_apply_cert(cfg, cert_pem, key_pem)
    if not success and old_cert_exists:
        log("新证书安装失败，旧证书仍然有效，请手动排查")
    elif not success:
        log("新证书安装失败")
    _set_action(cfg, "new" if success else "failed",
                "" if success else "新证书保存/部署失败")
    return success


# ---------- check mode ----------

def do_check(cfg: Config) -> None:
    if not cfg.domain:
        log("未指定 --domain / CERT_DOMAIN，仅检查本地证书文件")

    log("===== 本地证书检查 =====")
    if not cfg.cert_file.exists():
        log(f"证书文件不存在: {cfg.cert_file}")
    else:
        expiry = parse_cert_expiry(cfg.cert_file)
        if expiry is None:
            log("无法解析证书，建议运行 --renew")
        else:
            remaining = days_until_expiry(expiry)
            status = "正常" if remaining > cfg.renewal_days else "即将过期"
            log(f"证书域名: {cfg.domain or '(未配置)'}")
            log(f"证书路径: {cfg.cert_file}")
            log(f"私钥路径: {cfg.key_file}")
            if cfg.fullchain_file:
                log(f"完整链路径: {cfg.fullchain_file}")
            log(f"过期时间: {expiry.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            log(f"剩余天数: {remaining} 天  ({status})")
            if remaining <= cfg.renewal_days:
                log("建议运行 --renew 进行续期")

    if cfg.domain:
        log("")
        log("===== 平台证书检查 =====")
        platform_cert_id = find_valid_platform_cert(cfg.domain)
        if platform_cert_id:
            detail = get_certificate_detail(platform_cert_id)
            if detail:
                log(f"平台证书详情: cert_id={detail.get('cert_id')}, "
                    f"domain={detail.get('domain')}, "
                    f"sans={detail.get('sans')}, "
                    f"end_date={detail.get('end_date')}, "
                    f"has_key={'是' if detail.get('key') else '否'}")
            log("如需使用平台证书，运行 --renew 会自动下载")
        else:
            log("平台上未找到有效证书，运行 --renew 将自动申请新证书")


# ---------- 通知（QQ 邮箱 SMTP） ----------
#
# 默认关闭；NOTIFY_ENABLED=1 才启用。使用标准库 smtplib，无额外依赖。
# QQ 邮箱要点：SMTP_HOST=smtp.qq.com，SMTP_PORT=465（SSL），
# SMTP_PASSWORD 必须填「授权码」（QQ 邮箱 → 设置 → 账户 → POP3/IMAP/SMTP 服务 中生成），
# 不是 QQ 登录密码。

NOTIFY_DEFAULT_HOST = "smtp.qq.com"
NOTIFY_DEFAULT_PORT = 465
NOTIFY_DEFAULT_SECURITY = "ssl"
NOTIFY_SECURITIES = ("ssl", "starttls", "plain")


class NotifyConfig:
    """邮件通知配置（全部来自环境变量 / .env）"""
    enabled: bool = False
    host: str = NOTIFY_DEFAULT_HOST
    port: int = NOTIFY_DEFAULT_PORT
    security: str = NOTIFY_DEFAULT_SECURITY
    user: str = ""
    password: str = ""
    sender: str = ""
    recipients: List[str] = []
    on_noop: bool = False       # 是否在"无需续期"时也发通知（默认不发）
    timeout: int = 20


def _env_truthy(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return default
    return val.strip().lower() in ("1", "true", "yes", "on", "y", "t")


def load_notify_config() -> NotifyConfig:
    nc = NotifyConfig()
    nc.enabled = _env_truthy("NOTIFY_ENABLED")

    nc.host = (os.environ.get("SMTP_HOST") or "").strip() or NOTIFY_DEFAULT_HOST
    port_raw = (os.environ.get("SMTP_PORT") or "").strip()
    if port_raw:
        try:
            nc.port = int(port_raw)
        except ValueError:
            log(f"WARN: SMTP_PORT={port_raw!r} 非整数，使用默认 {NOTIFY_DEFAULT_PORT}")
            nc.port = NOTIFY_DEFAULT_PORT

    security = (os.environ.get("SMTP_SECURITY") or "").strip().lower() or NOTIFY_DEFAULT_SECURITY
    if security not in NOTIFY_SECURITIES:
        log(f"WARN: SMTP_SECURITY={security!r} 不支持（可选 {'/'.join(NOTIFY_SECURITIES)}），使用 {NOTIFY_DEFAULT_SECURITY}")
        security = NOTIFY_DEFAULT_SECURITY
    nc.security = security

    nc.user = (os.environ.get("SMTP_USER") or "").strip()
    nc.password = os.environ.get("SMTP_PASSWORD") or ""
    nc.sender = (os.environ.get("NOTIFY_FROM") or "").strip() or nc.user

    to_raw = (os.environ.get("NOTIFY_TO") or "").strip() or nc.user
    nc.recipients = [x.strip() for x in to_raw.replace(";", ",").split(",") if x.strip()]

    nc.on_noop = _env_truthy("NOTIFY_ON_NOOP")

    if nc.enabled:
        missing = []
        if not nc.user:
            missing.append("SMTP_USER")
        if not nc.password:
            missing.append("SMTP_PASSWORD")
        if not nc.recipients:
            missing.append("NOTIFY_TO")
        if missing:
            log(f"WARN: NOTIFY_ENABLED 已开启但缺少 {'/'.join(missing)}，本轮不发送邮件通知")
            nc.enabled = False
        else:
            log(f"邮件通知已启用: {nc.host}:{nc.port} ({nc.security}) -> {', '.join(nc.recipients)}")
    return nc


def send_notify_mail(nc: NotifyConfig, subject: str, body: str) -> bool:
    """发送通知邮件；任何失败只告警，绝不影响证书续期结果"""
    if not nc.enabled:
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = nc.sender
    msg["To"] = ", ".join(nc.recipients)
    msg.set_content(body)
    try:
        if nc.security == "ssl":
            server = smtplib.SMTP_SSL(nc.host, nc.port, timeout=nc.timeout)
        else:
            server = smtplib.SMTP(nc.host, nc.port, timeout=nc.timeout)
        with server:
            server.ehlo()
            if nc.security == "starttls":
                server.starttls()
                server.ehlo()
            if nc.user:
                server.login(nc.user, nc.password)
            server.send_message(msg)
        log(f"通知邮件已发送: {subject} -> {', '.join(nc.recipients)}")
        return True
    except Exception as e:
        log(f"WARN: 通知邮件发送失败（证书续期结果不受影响）: {e}")
        return False


def _cert_status_lines(cfg: Config) -> List[str]:
    """通知正文里的证书状态摘要"""
    lines = [f"证书文件: {cfg.cert_file}", f"私钥文件: {cfg.key_file}"]
    lines.append(f"完整链文件: {cfg.fullchain_file if cfg.fullchain_file else '(已关闭)'}")
    expiry = parse_cert_expiry(cfg.cert_file) if cfg.cert_file.exists() else None
    if expiry:
        lines.append(f"证书过期时间: {expiry.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"剩余天数: {days_until_expiry(expiry)} 天（续期阈值 {cfg.renewal_days} 天）")
    else:
        lines.append("证书过期时间: (无法解析或文件不存在)")
    return lines


def notify_renew_outcome(nc: NotifyConfig, cfg: Config, ok: bool) -> None:
    """按动作类型决定是否发信：失败必发；实际续期(新建/复用)发；无需续期默认不发"""
    if not nc.enabled:
        return

    action = cfg.last_action or ("failed" if not ok else "new")
    if ok and action == "skip" and not nc.on_noop:
        log("无需续期且 NOTIFY_ON_NOOP 未开启，跳过邮件通知")
        return

    domain = cfg.domain or "(未配置域名)"
    if not ok:
        subject = f"[证书续期失败] {domain}"
        result = "失败" + (f"（{cfg.last_error}）" if cfg.last_error else "")
    elif action == "platform":
        subject = f"[证书续期成功] {domain}（复用平台证书）"
        result = "成功：已从平台下载并部署证书（未重新签发）"
    elif action == "skip":
        subject = f"[证书检查] {domain} 无需续期"
        result = "无需处理：本地证书仍在有效期内"
    else:
        subject = f"[证书续期成功] {domain}（新签发）"
        result = "成功：已申请并部署新证书"

    header = [
        f"域名: {domain}",
        f"结果: {result}",
        f"时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"密钥模式: {KEY_MODE_LABEL}",
    ]
    body = "\n".join(header + _cert_status_lines(cfg)) + "\n\n----- 本轮运行日志 -----\n" + "\n".join(_RUN_LOG) + "\n"
    send_notify_mail(nc, subject, body)


# ---------- arg parsing ----------

def parse_args(argv=None) -> Config:
    parser = argparse.ArgumentParser(
        description="阿里云 SSL 证书自动管理",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
示例:
  # 检查证书状态
  %(prog)s --check --domain example.com --cert-dir ./certs

  # 自动续期（本地 → 平台 → 新建）
  %(prog)s --renew --domain example.com --cert-dir ./certs

  # 强制重新申请，并指定私钥/证书文件路径
  %(prog)s --force-renew --domain example.com \\
      --cert-file /etc/nginx/certs/example.com.pem \\
      --key-file /etc/nginx/certs/example.com.key

  # 申请付费 OV 证书（需先在阿里云购买资源包）
  %(prog)s --renew --domain example.com --cert-type ov

  # 自定义 reload 命令（如通过 docker）
  %(prog)s --renew --domain example.com --reload-cmd "docker compose restart blog"

  # 续期后不执行 reload（容器部署常用，如证书由其他服务 watch）
  %(prog)s --renew --domain example.com --no-reload

  # 守护进程模式（容器化部署推荐）
  %(prog)s --daemon --interval-hours 12 --domain example.com
""",
    )

    mode = parser.add_argument_group("运行模式")
    mode.add_argument("--check", action="store_true", help="检查本地和平台证书有效期")
    mode.add_argument("--renew", action="store_true", help="三步检查 (本地→平台→新建) 并自动续期")
    mode.add_argument("--force-renew", action="store_true",
                      help="跳过本地和平台检查，强制重新申请")

    cert_opts = parser.add_argument_group("证书输出路径（二选一：--cert-dir 或显式文件路径）")
    cert_opts.add_argument("--cert-dir", default=None,
                           help=f"证书存放目录 (默认 {DEFAULT_CERT_DIR}，写入 cert.pem/key.pem/fullchain.pem)")
    cert_opts.add_argument("--cert-file", default=None,
                           help="证书文件路径（覆盖 --cert-dir/cert.pem）")
    cert_opts.add_argument("--key-file", default=None,
                           help="私钥文件路径（覆盖 --cert-dir/key.pem）")
    cert_opts.add_argument("--fullchain-file", default=None,
                           help="完整链证书路径（覆盖 --cert-dir/fullchain.pem；"
                                "显式传空字符串可关闭输出）")
    cert_opts.add_argument("--no-fullchain", action="store_true",
                           help="不写出 fullchain.pem（等价于 FULLCHAIN_FILE=\"\"）")

    domain_opts = parser.add_argument_group("域名 / 证书类型")
    domain_opts.add_argument("--domain", default=None,
                            help="证书主域名 (可由环境变量 CERT_DOMAIN 提供)")
    domain_opts.add_argument("--san", default=None,
                            help="【不支持】平台托管模式不传 CSR/SAN，SAN 由阿里云按主域名自动匹配，"
                                 "传入此参数仅会打印告警并被忽略")
    domain_opts.add_argument("--dns-domain", default=None,
                            help="阿里云 DNS 托管域名，用于自动添加验证记录 (默认同 --domain)")
    domain_opts.add_argument("--renewal-days", type=int, default=None,
                            help=f"提前多少天触发续期 (默认 {DEFAULT_RENEWAL_DAYS})")
    domain_opts.add_argument("--cert-type", default=None,
                            choices=list(CERT_TYPE_PRESETS.keys()),
                            help="证书类型预设 (默认 free-dv)")
    domain_opts.add_argument("--product-code", default=None,
                            help="阿里云 product_code（覆盖 --cert-type，便于使用未预设的代码）")

    deploy_opts = parser.add_argument_group("部署 / 重载")
    deploy_opts.add_argument("--no-reload", action="store_true",
                             help="不执行 reload 命令（默认会执行 nginx -s reload）")
    deploy_opts.add_argument("--reload-cmd", default=None,
                             help='自定义 reload 命令，如 "docker compose restart blog"')

    daemon_opts = parser.add_argument_group("守护进程（容器化部署）")
    daemon_opts.add_argument("--daemon", action="store_true",
                             help=f"以守护进程模式运行，周期性执行 --renew（默认间隔 {DEFAULT_INTERVAL_HOURS} 小时）")
    daemon_opts.add_argument("--interval-hours", type=float, default=None,
                             help=f"守护进程检查间隔（小时），可由环境变量 INTERVAL_HOURS 提供，默认 {DEFAULT_INTERVAL_HOURS}")
    daemon_opts.add_argument("--run-once", action="store_true",
                             help="守护进程模式下立即执行一次后退出（用于调试）")

    misc = parser.add_argument_group("其他")
    misc.add_argument("--env-file", default=None,
                      help="加载指定的 .env 文件（默认依次查找 ./ 和脚本所在目录）")

    args = parser.parse_args(argv)

    # 加载 .env
    env_candidates = []
    if args.env_file:
        env_candidates.append(Path(args.env_file))
    else:
        env_candidates.append(Path.cwd() / ".env")
        env_candidates.append(Path(__file__).resolve().parent / ".env")
        env_candidates.append(Path(__file__).resolve().parent.parent / ".env")
    for candidate in env_candidates:
        if candidate.exists():
            try:
                from dotenv import load_dotenv
                load_dotenv(candidate, override=False)
                log(f"已加载环境变量: {candidate}")
            except ImportError:
                # 没有 python-dotenv 也可以用最简单的 KEY=VALUE 解析
                _load_env_simple(candidate)
                log(f"已加载环境变量: {candidate}")
            break

    cfg = Config()

    # domain
    cfg.domain = args.domain or os.environ.get("CERT_DOMAIN", "")
    cfg.dns_domain = (args.dns_domain or os.environ.get("ALIBABA_DNS_DOMAIN", "")
                      or cfg.domain)

    # SAN：本项目只使用平台托管模式（不传 CSR），SAN 由阿里云按主域名自动匹配，
    # 因此 --san / CERT_SANS 一律忽略，但要明确告警而不是静默丢弃
    raw_sans = args.san if args.san is not None else os.environ.get("CERT_SANS", "")
    if raw_sans.strip():
        log(f"WARN: 平台托管模式不支持自定义 SAN（收到 {raw_sans!r}），已忽略；"
            f"需要额外 SAN 请在阿里云 SSL 证书控制台手动申请")

    # renewal days
    if args.renewal_days is not None:
        cfg.renewal_days = args.renewal_days
    elif os.environ.get("RENEWAL_DAYS"):
        try:
            cfg.renewal_days = int(os.environ["RENEWAL_DAYS"])
        except ValueError:
            log(f"WARN: RENEWAL_DAYS={os.environ['RENEWAL_DAYS']!r} 非整数，使用默认 {DEFAULT_RENEWAL_DAYS}")
            cfg.renewal_days = DEFAULT_RENEWAL_DAYS
    else:
        cfg.renewal_days = DEFAULT_RENEWAL_DAYS

    # product code
    cert_type = args.cert_type or os.environ.get("CERT_TYPE", "free-dv")
    if cert_type not in CERT_TYPE_PRESETS:
        log(f"WARN: 未知 cert-type {cert_type!r}，回退到 free-dv")
        cert_type = "free-dv"
    cfg.product_code = args.product_code or os.environ.get("PRODUCT_CODE") or CERT_TYPE_PRESETS[cert_type]

    # cert dir / files
    cert_dir = args.cert_dir or os.environ.get("CERT_DIR", DEFAULT_CERT_DIR)
    cfg.cert_dir = Path(cert_dir).expanduser()
    cfg.cert_file = Path(args.cert_file or os.environ.get("CERT_FILE") or (cfg.cert_dir / "cert.pem")).expanduser()
    cfg.key_file = Path(args.key_file or os.environ.get("KEY_FILE") or (cfg.cert_dir / "key.pem")).expanduser()

    # fullchain: 必须区分「未设置」和「显式置空」两种情况——
    #   未设置           → 默认 <cert_dir>/fullchain.pem
    #   显式空字符串     → 关闭输出（注意 Path("") 会退化成 "."，不能用真值/空串比较来判断）
    #   --no-fullchain   → 关闭输出
    if args.no_fullchain:
        cfg.fullchain_file = None
        log("已通过 --no-fullchain 关闭 fullchain 输出")
    else:
        raw_fullchain = (args.fullchain_file if args.fullchain_file is not None
                         else os.environ.get("FULLCHAIN_FILE"))
        if raw_fullchain is not None and raw_fullchain.strip() == "":
            cfg.fullchain_file = None
            log("FULLCHAIN_FILE 为空字符串，已关闭 fullchain 输出")
        elif raw_fullchain:
            cfg.fullchain_file = Path(raw_fullchain).expanduser()
        else:
            cfg.fullchain_file = cfg.cert_dir / "fullchain.pem"

    # reload
    if args.no_reload:
        cfg.no_reload = True
    elif os.environ.get("NO_RELOAD") in ("1", "true", "yes", "TRUE", "YES", "True"):
        cfg.no_reload = True
    cfg.reload_cmd = args.reload_cmd or os.environ.get("RELOAD_CMD")

    # daemon
    # 运行模式遵循 README 承诺的优先级：命令行 > 环境变量。
    # 镜像内默认 ENV DAEMON=1，但用户显式传了 --check/--renew/--force-renew 时，
    # 应由命令行决定模式，否则容器里连 --check 都会变成守护进程长跑。
    _truthy = ("1", "true", "yes", "TRUE", "YES", "True")
    cli_mode_given = args.check or args.renew or args.force_renew
    if cli_mode_given and os.environ.get("DAEMON") in _truthy:
        log("命令行已指定运行模式，忽略环境变量 DAEMON=1")
    cfg.daemon = args.daemon or (not cli_mode_given and os.environ.get("DAEMON") in _truthy)
    if args.interval_hours is not None:
        cfg.interval_hours = args.interval_hours
    elif os.environ.get("INTERVAL_HOURS"):
        try:
            cfg.interval_hours = float(os.environ["INTERVAL_HOURS"])
        except ValueError:
            log(f"WARN: INTERVAL_HOURS={os.environ['INTERVAL_HOURS']!r} 非数字，使用默认 {DEFAULT_INTERVAL_HOURS}")
            cfg.interval_hours = DEFAULT_INTERVAL_HOURS
    else:
        cfg.interval_hours = DEFAULT_INTERVAL_HOURS
    cfg.run_once = args.run_once
    cfg.force_renew = args.force_renew
    cfg.renew = args.renew
    cfg.check = args.check

    return cfg


def _load_env_simple(path: Path) -> None:
    """简易 .env 解析（无 python-dotenv 时使用）"""
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)


# ---------- main ----------

_STOP = False


def _handle_signal(signum, frame):
    """优雅退出 daemon"""
    global _STOP
    log(f"收到信号 {signum}，准备退出 ...")
    _STOP = True


def run_daemon(cfg: Config) -> None:
    """守护进程：周期性执行 --renew（或 --force-renew，仅限 --run-once），
    间隔由 cfg.interval_hours 控制"""
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # --force-renew 会跳过本地/平台检查直接重新签发，长跑会每轮重复签发，
    # 因此只允许配合 --run-once（main() 已做校验），此处再兜底一次
    renew_fn = do_renew_force if cfg.force_renew else do_renew
    if cfg.force_renew:
        log("daemon: --force-renew 已启用（跳过本地/平台检查，强制重新申请）")

    interval_seconds = max(60, int(cfg.interval_hours * 3600))
    log(f"启动 daemon：每 {cfg.interval_hours:g} 小时执行一次续期检查 (PID={os.getpid()})")
    log(f"首次执行立即开始，之后按间隔周期运行；收到 SIGTERM/SIGINT 优雅退出")

    notify_cfg = load_notify_config()

    while not _STOP:
        reset_run_log()
        log("===== daemon: 触发续期检查 =====")
        try:
            ok = renew_fn(cfg)
            notify_renew_outcome(notify_cfg, cfg, ok)
        except Exception as e:
            log(f"daemon: 续期异常（不退出，等待下一轮）: {e}")
            _set_action(cfg, "failed", f"未捕获异常: {e}")
            notify_renew_outcome(notify_cfg, cfg, False)

        if cfg.run_once:
            log("--run-once 已设置，daemon 在执行一次后退出")
            break

        # 分片 sleep 以便及时响应信号
        slept = 0
        while slept < interval_seconds and not _STOP:
            time.sleep(min(5, interval_seconds - slept))
            slept += 5

    log("daemon 已退出")


def main() -> None:
    cfg = parse_args()

    # 模式冲突校验（先于凭证校验，确保用户能看到真正的问题）
    if cfg.daemon:
        if cfg.force_renew and not cfg.run_once:
            log("错误: --daemon + --force-renew 会每轮跳过检查强制重新签发证书，已拒绝启动")
            log("  只需强制签发一次: --daemon --force-renew --run-once")
            log("  长期守护请去掉 --force-renew（--renew 的三步检查本身就包含按需续期）")
            sys.exit(2)
        if cfg.check:
            log("WARN: --daemon 模式下 --check 被忽略，daemon 只执行续期检查")

    ak_id = os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_ID", "")
    ak_secret = os.environ.get("ALIBABA_CLOUD_ACCESS_KEY_SECRET", "")
    if not ak_id or not ak_secret:
        log("错误: 请设置 ALIBABA_CLOUD_ACCESS_KEY_ID 和 ALIBABA_CLOUD_ACCESS_KEY_SECRET")
        log("  可在 .env 文件中配置，或通过环境变量传入")
        sys.exit(1)

    if cfg.daemon:
        run_daemon(cfg)
        return

    if cfg.force_renew:
        reset_run_log()
        notify_cfg = load_notify_config()
        ok = do_renew_force(cfg)
        notify_renew_outcome(notify_cfg, cfg, ok)
        sys.exit(0 if ok else 1)

    if cfg.renew:
        reset_run_log()
        notify_cfg = load_notify_config()
        ok = do_renew(cfg)
        notify_renew_outcome(notify_cfg, cfg, ok)
        sys.exit(0 if ok else 1)

    do_check(cfg)


if __name__ == "__main__":
    main()
