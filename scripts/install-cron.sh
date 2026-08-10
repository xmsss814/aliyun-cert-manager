#!/usr/bin/env bash
# install-cron.sh — 为 aliyun-cert-manager 安装 cron 定时续期
#
# 用法:
#   bash scripts/install-cron.sh                                 # 默认每天 03:17 执行 --renew
#   CRON_SCHEDULE="17 3 * * *" bash scripts/install-cron.sh \
#       --domain example.com --cert-dir /etc/nginx/certs
#
# 环境变量:
#   CRON_SCHEDULE  5 字段 cron 表达式 (默认 "17 3 * * *")
#   LOG_FILE       日志输出路径 (默认 ~/aliyun-cert-manager.log)
#   PYTHON_BIN     Python 解释器 (默认 python3，未找到则用脚本目录的 .venv/bin/python)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MARKER="# aliyun-cert-manager:auto ($PROJECT_DIR)"
CRON_SCHEDULE="${CRON_SCHEDULE:-17 3 * * *}"
LOG_FILE="${LOG_FILE:-$HOME/aliyun-cert-manager.log}"

# 转发附加参数到 cert_manager.py --renew
EXTRA_ARGS=("$@")

# 选择 Python 解释器
PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
    PYTHON_BIN="$PROJECT_DIR/.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  else
    echo "ERROR: 未找到 python3，请先安装或设置 PYTHON_BIN" >&2
    exit 1
  fi
fi

# 组装 cron 命令
# 注意: cron 默认 PATH 很有限，明示 PATH 与工作目录
read -r -a SCHED_PARTS <<< "$CRON_SCHEDULE"
if [[ ${#SCHED_PARTS[@]} -ne 5 ]]; then
  echo "ERROR: CRON_SCHEDULE 必须是 5 字段表达式，当前为: $CRON_SCHEDULE" >&2
  exit 1
fi

# 构造 cert_manager.py 的参数串
ARGS_STR="--renew"
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  for a in "${EXTRA_ARGS[@]}"; do
    # 简单转义：包含空格的参数加引号
    if [[ "$a" == *" "* || "$a" == *'"'* ]]; then
      printf -v a_esc '%q' "$a"
      ARGS_STR="$ARGS_STR $a_esc"
    else
      ARGS_STR="$ARGS_STR $a"
    fi
  done
fi

CRON_CMD="$PYTHON_BIN '$PROJECT_DIR/scripts/cert_manager.py' $ARGS_STR >> '$LOG_FILE' 2>&1"
CRON_LINE="$CRON_SCHEDULE cd '$PROJECT_DIR' && $CRON_CMD $MARKER"

# 移除已有同项目标记的 cron 行，再追加
TEMP_CRON="$(mktemp)"
cleanup() { rm -f "$TEMP_CRON"; }
trap cleanup EXIT

if crontab -l 2>/dev/null | grep -v -F "$MARKER" > "$TEMP_CRON"; then
  :
fi
echo "$CRON_LINE" >> "$TEMP_CRON"

crontab "$TEMP_CRON"

echo "✓ cron 已安装"
echo "  表达式:    $CRON_SCHEDULE"
echo "  Python:    $PYTHON_BIN"
echo "  脚本:      $PROJECT_DIR/scripts/cert_manager.py"
echo "  附加参数:  ${EXTRA_ARGS[*]:-(无)}"
echo "  日志:      $LOG_FILE"
echo
echo "查看:    crontab -l | grep -A1 -B1 'aliyun-cert-manager:auto'"
echo "卸载:    bash $SCRIPT_DIR/uninstall-cron.sh"
