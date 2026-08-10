#!/usr/bin/env bash
# uninstall-cron.sh — 卸载 aliyun-cert-manager 的 cron 定时任务
#
# 用法:
#   bash scripts/uninstall-cron.sh
#
# 通过 MARKER 行（由 install-cron.sh 写入）精确匹配并删除；不动其他 cron 任务。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MARKER="# aliyun-cert-manager:auto ($PROJECT_DIR)"

if ! crontab -l >/dev/null 2>&1; then
  echo "当前用户没有 crontab，无需卸载"
  exit 0
fi

COUNT_BEFORE=$(crontab -l 2>/dev/null | grep -c -F "$MARKER" || true)

if [[ "$COUNT_BEFORE" -eq 0 ]]; then
  echo "未找到本项目的 cron 任务（marker: $MARKER）"
  exit 0
fi

TEMP_CRON="$(mktemp)"
cleanup() { rm -f "$TEMP_CRON"; }
trap cleanup EXIT

crontab -l 2>/dev/null | grep -v -F "$MARKER" > "$TEMP_CRON" || true
crontab "$TEMP_CRON"

COUNT_AFTER=$(crontab -l 2>/dev/null | grep -c -F "$MARKER" || true)

echo "✓ 已移除 $((COUNT_BEFORE - COUNT_AFTER)) 条 cron 任务"
if [[ "$COUNT_AFTER" -gt 0 ]]; then
  echo "WARN: 仍有 $COUNT_AFTER 条 marker 残留，请检查 crontab -l"
  exit 1
fi
