#!/usr/bin/env bash
# 校园网自动登录 - macOS 双击启动脚本
# 在访达中双击本文件即可打开控制台(首次可能需要先执行: chmod +x start.command)
cd "$(dirname "$0")" || exit 1
exec python3 campus_net.py
