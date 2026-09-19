#!/usr/bin/env bash
# 校园网自动登录 - Linux / macOS 启动脚本
# 用法: ./start.sh  (需要已安装 python3)
cd "$(dirname "$0")" || exit 1
exec python3 campus_net.py
