# -*- coding: utf-8 -*-
"""
校园网自动登录工具 (锐捷 SAM + CAS-SSO 网页认证体系)
单文件应用: 网页控制台 + 命令行登录

用法:
    python campus_net.py            # 启动网页控制台(环境安装/账号配置/开机自启/连接)
    python campus_net.py --login    # 无界面直接认证(供开机自启使用)
    python campus_net.py --force    # 强制完整认证一次(排障用)
    python campus_net.py --logout   # 下线: 断开当前认证

首次使用: 运行 python campus_net.py, 在网页控制台中完成配置
"""
import base64
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# 说明: requests / pycryptodome 在函数内部按需导入,
#       使网页控制台在未安装依赖时也能启动(可先用「一键配置环境」安装)

# ================================================================
#  常量与默认配置
# ================================================================

ROOT = Path(__file__).resolve().parent
CONFIG_FILE = ROOT / "config.json"
LOG_FILE = ROOT / "login.log"
MIRROR_URL = "https://pypi.tuna.tsinghua.edu.cn/simple"
TIMEOUT = 8

DEFAULT_CONFIG = {
    "username": "",
    "password": "",
    "host": "http://110.184.24.61",
    "probe_url": "http://connect.rom.miui.com/generate_204",
    "custom_page_id": "",
    "skip_online_check": False,     # 开机优化: 跳过"是否已在线"检测(省约2秒)
    "gateway": {"userip": "", "nasip": "", "mac": ""},
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
}

_config_cache = None


# ================================================================
#  配置读写
# ================================================================

def get_config(strict: bool = False) -> dict:
    """读取配置(与默认值合并); strict=True 时配置缺失则退出(命令行登录用)"""
    global _config_cache
    if _config_cache is None:
        data = {}
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                print(f"[×] 配置文件读取失败: {exc}")
                if strict:
                    sys.exit(1)
                data = {}
        elif strict:
            print("[×] 未找到配置文件 config.json")
            print("    请先运行:  python campus_net.py  在控制台中完成配置")
            sys.exit(1)

        merged = dict(DEFAULT_CONFIG)
        merged.update(data)
        gateway = dict(DEFAULT_CONFIG["gateway"])
        gateway.update(data.get("gateway") or {})
        merged["gateway"] = gateway
        _config_cache = merged
    return _config_cache


def reload_config():
    """配置文件被网页控制台修改后刷新缓存"""
    global _config_cache
    _config_cache = None


def get_host() -> str:
    return get_config().get("host") or DEFAULT_CONFIG["host"]


def get_probe_url() -> str:
    return get_config().get("probe_url") or DEFAULT_CONFIG["probe_url"]


def get_gateway() -> dict:
    return get_config().get("gateway") or {}


# ================================================================
#  认证核心
# ================================================================

def check_online(timeout: float = TIMEOUT) -> bool:
    """联网检测: 认证后探测地址返回 204, 未认证会被网关劫持"""
    import requests
    try:
        r = requests.get(get_probe_url(), timeout=timeout, allow_redirects=False)
        return r.status_code == 204
    except requests.RequestException:
        return False


def wait_network_ready(timeout_s: int = 15) -> bool:
    """开机场景: 等待网卡/校园网就绪(能连上认证服务器), 最多 15 秒

    单次超时 1.5 秒 + 重试间隔 0.5 秒: 网络一通就能立刻发现,
    而不是每轮干等 5 秒超时再等 3 秒(原先网络 1 秒后就绪也要等 8 秒才被感知)。
    """
    import requests
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            requests.get(get_host() + "/", timeout=1.5, allow_redirects=False)
            return True
        except requests.RequestException:
            time.sleep(0.5)
    return False


def aes_encrypt_b64(key_b64: str, plaintext: str) -> str:
    """与登录页 JS 的 AES 加密保持一致: AES-128-ECB + Pkcs7, base64 输出"""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    cipher = AES.new(base64.b64decode(key_b64), AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(plaintext.encode(), 16))).decode()


def _remember_gateway(userip: str, nasip: str):
    """把 nasip / userip 写回 config.json, 使之后的开机都能走快速通道"""
    try:
        data = (json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                if CONFIG_FILE.exists() else {})
    except (OSError, json.JSONDecodeError):
        return
    gw = dict(data.get("gateway") or {})
    if userip:
        gw["userip"] = userip
    if nasip:
        gw["nasip"] = nasip
    data["gateway"] = gw
    try:
        CONFIG_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
    except OSError:
        pass


def fast_login(force: bool = False) -> bool:
    """纯 HTTP 认证, 正常 < 1 秒 (调用前请确保已配置且网络就绪)"""
    import requests
    cfg = get_config(strict=True)
    username = cfg.get("username", "")
    password = cfg.get("password", "")
    host = get_host()
    probe = get_probe_url()
    gateway = get_gateway()

    s = requests.Session()
    s.headers.update(HEADERS)

    def _extract_session(urls):
        return re.search(r"sessionId=([0-9a-f]{8,})", " ".join(urls))

    def _first(urls, *pats):
        text = " ".join(urls)
        for p in pats:
            m = re.search(p, text)
            if m:
                return m.group(1)
        return ""

    def _entry_url(userip, nasip, mac):
        """网关入口地址(直接访问它可跳过外部探测的多跳跳转)"""
        return (f"{host}/eportal/index.jsp?userip={userip}&wlanacname="
                f"&nasip={nasip}&wlanparameter={mac}&url={urllib.parse.quote(probe)}")

    def _do_login(sid, userip, nasip, page_id, online_wait_s=15,
                  bail_if_not_online=False):
        """拿到会话参数后执行 CAS 登录(步骤 2~5), 返回是否成功"""
        # ---- 2. 获取 SSO 登录页, 解析加密密钥 ----
        cas_url = (f"{host}/cas-sso/login?flowSessionId={sid}&customPageId={page_id}"
                   f"&preview=false&appType=normal&language=zh-CN"
                   f"&timer={int(time.time()*1000)}&nasIp={nasip}&userIp={userip}"
                   f"&accept-language=zh-CN")
        try:
            r2 = s.get(cas_url, timeout=TIMEOUT)
        except requests.RequestException as e:
            print(f"[!] 获取登录页失败: {e}")
            return False

        key_m = re.search(r'id="login-croypto"[^>]*>([^<]+)<', r2.text)
        flow_m = re.search(r'id="login-page-flowkey"[^>]*>([^<]+)<', r2.text)
        if not key_m or not flow_m:
            print("[!] 登录页结构异常(未找到密钥), 该站可能非本工具适配的认证系统")
            return False
        key, flowkey = key_m.group(1).strip(), flow_m.group(1).strip()

        # ---- 3. 提交认证 ----
        form = {
            "username": username,
            "type": "UsernamePassword",
            "password": aes_encrypt_b64(key, password),
            "croypto": key,
            "captcha_payload": aes_encrypt_b64(key, "{}"),
            "execution": flowkey,
            "_eventId": "submit",
            "geolocation": "",
        }
        r3 = s.post(cas_url, data=form, timeout=TIMEOUT, allow_redirects=False,
                    headers={"Referer": cas_url, "Origin": host})
        loc = r3.headers.get("Location", "")
        if r3.status_code != 302 or "ticket=" not in loc:
            print(f"[!] 提交认证未成功 (状态码 {r3.status_code}), 请检查账号密码")
            return False
        print("[√] 凭据已被接受, 票据已签发")

        # ---- 4. 完成认证流程, 确认会话是否真正上线 ----
        session_online = False
        try:
            s.get(urllib.parse.urljoin(cas_url, loc), timeout=TIMEOUT)
            s.post(f"{host}/eportal/workFlow/getCurrentNode", timeout=TIMEOUT,
                   json={"sessionId": sid, "flowKey": "portal_auth"},
                   headers={"Content-Type": "application/json"})
            r_online = s.post(f"{host}/eportal/network/userOnline", timeout=TIMEOUT,
                              json={"sessionId": sid},
                              headers={"Content-Type": "application/json"})
            session_online = bool((r_online.json().get("data") or {}).get("online"))
        except (requests.RequestException, ValueError):
            pass

        if session_online:
            print("[√] 门户会话已上线")
        elif bail_if_not_online:
            # 门户未把本会话记录为在线: 设备实际在线则直接成功, 否则无需等待、立即退回
            # (刚下线后网关存在短暂缓冲窗口, 该窗口内等待无意义)
            if check_online():
                print("[√] 网络实际已连通")
                return True
            print("[!] 会话未被网关放行(可能处于下线缓冲窗口)")
            return False
        else:
            # 设备已在线时 NAS 会拒绝重复认证(ACK_AUTH_REFUSE), 属正常情况
            print("[!] 门户会话未建立(设备可能已在线), 以实际联网状态为准")

        # ---- 5. 等待联网生效(轮询间隔 0.3 秒) ----
        deadline = time.time() + online_wait_s
        while time.time() < deadline:
            if check_online():
                return True
            time.sleep(0.3)
        return check_online()

    def _local_ip():
        """本机当前使用的 IPv4: 快速通道的 userip 必须用当前 IP(缓存的会过期)"""
        import socket
        try:
            sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sk.connect((urllib.parse.urlsplit(host).hostname or "127.0.0.1", 80))
                return sk.getsockname()[0]
            finally:
                sk.close()
        except OSError:
            return ""

    # ---- 1a. 快速通道: 用缓存的 nasip 直连网关入口, 单个请求即可拿到会话(约 0.02 秒)
    #      相比"外部探测地址被劫持 → 多跳跳转"可省约 2 秒; 拿不到则退回标准链路 ----
    gw_nasip = (gateway.get("nasip") or "").strip()
    if gw_nasip and not force:
        cur_ip = _local_ip() or gateway.get("userip") or "127.0.0.1"
        try:
            r0 = s.get(_entry_url(cur_ip, gw_nasip, gateway.get("mac") or ""),
                       timeout=3, allow_redirects=False)
            loc0 = r0.headers.get("Location", "")
            m0 = _extract_session([loc0])
        except requests.RequestException:
            m0 = None
        if m0:
            f_sid = m0.group(1)
            f_ip = _first([loc0], r"userIp=([\d.]+)", r"userip=([\d.]+)") or cur_ip
            f_nas = _first([loc0], r"nasIp=([\d.]+)", r"nasip=([\d.]+)") or gw_nasip
            f_page = (_first([loc0], r"customPageId=([0-9a-f]+)")
                      or (cfg.get("custom_page_id") or ""))
            print(f"[*] 会话 {f_sid} (快速通道, ip={f_ip})")
            # 会话未被网关记录为在线时立即退回(无需等待); 被记录为在线则最多等 3 秒生效
            if _do_login(f_sid, f_ip, f_nas, f_page, online_wait_s=3,
                         bail_if_not_online=True):
                _remember_gateway(f_ip, f_nas)
                return True
            print("[!] 快速通道未成功, 改用标准链路重试")

    # ---- 1b. 标准链路: 探测地址被网关劫持(force 模式则直连入口) ----
    if force:
        gw_userip = gateway.get("userip") or "127.0.0.1"
        gw_nasip = gateway.get("nasip") or ""
        gw_mac = gateway.get("mac") or ""
        try:
            r = s.get(_entry_url(gw_userip, gw_nasip, gw_mac),
                      timeout=TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            print(f"[!] 无法连接认证服务器, 请确认已连接校园网: {e}")
            return False
        chain = [probe, r.url]
    else:
        try:
            r = s.get(probe, timeout=TIMEOUT, allow_redirects=True)
        except requests.RequestException as e:
            print(f"[!] 访问探测地址失败: {e}")
            return False
        chain = [probe] + [h.headers.get("Location", "") for h in r.history] + [r.url]

    m = _extract_session(chain)
    if not m:
        # 拿不到 sessionId: 可能设备其实已在线, 或探测请求刚好抖动;
        # 复查联网状态并重试, 避免开机网络未稳时误判失败
        if check_online():
            print("[√] 网络实际已连通, 无需登录")
            return True
        for _ in range(3):
            time.sleep(2)
            try:
                r = s.get(probe, timeout=TIMEOUT, allow_redirects=True)
            except requests.RequestException:
                continue
            chain = ([probe] + [h.headers.get("Location", "") for h in r.history]
                     + [r.url])
            m = _extract_session(chain)
            if m:
                break
            if check_online():
                print("[√] 网络实际已连通, 无需登录")
                return True
        if not m:
            print("[!] 未从跳转链中拿到 sessionId (可能不在校园网内或认证流程已变化)")
            return False

    joined = " ".join(chain)        # 供下方提取其余网关参数(含重试后的最终链)
    sid = m.group(1)
    userip = _first([joined], r"userIp=([\d.]+)", r"userip=([\d.]+)") or gateway.get("userip", "")
    nasip = _first([joined], r"nasIp=([\d.]+)", r"nasip=([\d.]+)") or gateway.get("nasip", "")
    page_id = _first([joined], r"customPageId=([0-9a-f]+)") or (cfg.get("custom_page_id") or "")
    print(f"[*] 会话 {sid} (标准链路, ip={userip})")

    if _do_login(sid, userip, nasip, page_id):
        _remember_gateway(userip, nasip)
        return True
    return False


def fast_logout() -> bool:
    """下线: 先在该会话上完成登录(门户下线接口要求会话处于在线状态), 再调用下线接口"""
    import socket

    import requests
    cfg = get_config(strict=True)
    username = cfg.get("username", "")
    password = cfg.get("password", "")
    host = get_host()
    probe = get_probe_url()
    gateway = get_gateway()

    s = requests.Session()
    s.headers.update(HEADERS)

    # 1. 拿会话(入口直连; userip 用当前本机 IP)
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sk.connect((urllib.parse.urlsplit(host).hostname or "127.0.0.1", 80))
            userip = sk.getsockname()[0]
        finally:
            sk.close()
    except OSError:
        userip = gateway.get("userip") or "127.0.0.1"
    entry = (f"{host}/eportal/index.jsp?userip={userip}&wlanacname="
             f"&nasip={gateway.get('nasip') or ''}&wlanparameter={gateway.get('mac') or ''}"
             f"&url={urllib.parse.quote(probe)}")
    try:
        r0 = s.get(entry, timeout=5, allow_redirects=False)
    except requests.RequestException as e:
        print(f"[!] 无法连接认证服务器: {e}")
        return False
    loc0 = r0.headers.get("Location", "")
    m = re.search(r"sessionId=([0-9a-f]{8,})", loc0)
    if not m:
        print("[!] 未取到会话(不在校园网内或网关参数缺失)")
        return False
    sid = m.group(1)
    m2 = re.search(r"customPageId=([0-9a-f]+)", loc0)
    page_id = m2.group(1) if m2 else (cfg.get("custom_page_id") or "")
    m3 = re.search(r"nasIp=([\d.]+)", loc0)
    nasip = m3.group(1) if m3 else (gateway.get("nasip") or "")

    # 2. 在该会话上完成登录(下线接口对未登录会话无效, 已实测)
    cas_url = (f"{host}/cas-sso/login?flowSessionId={sid}&customPageId={page_id}"
               f"&preview=false&appType=normal&language=zh-CN"
               f"&timer={int(time.time()*1000)}&nasIp={nasip}&userIp={userip}"
               f"&accept-language=zh-CN")
    try:
        r1 = s.get(cas_url, timeout=TIMEOUT)
    except requests.RequestException as e:
        print(f"[!] 获取登录页失败: {e}")
        return False
    key_m = re.search(r'id="login-croypto"[^>]*>([^<]+)<', r1.text)
    flow_m = re.search(r'id="login-page-flowkey"[^>]*>([^<]+)<', r1.text)
    if key_m and flow_m:
        key = key_m.group(1).strip()
        form = {
            "username": username,
            "type": "UsernamePassword",
            "password": aes_encrypt_b64(key, password),
            "croypto": key,
            "captcha_payload": aes_encrypt_b64(key, "{}"),
            "execution": flow_m.group(1).strip(),
            "_eventId": "submit",
            "geolocation": "",
        }
        try:
            s.post(cas_url, data=form, timeout=TIMEOUT, allow_redirects=False,
                   headers={"Referer": cas_url, "Origin": host})
        except requests.RequestException:
            pass

    # 3. 调用官方下线接口
    try:
        r2 = s.post(f"{host}/eportal/network/offline", timeout=TIMEOUT,
                    json={"sessionId": sid},
                    headers={"Content-Type": "application/json",
                             "Referer": host + "/portal/"})
    except requests.RequestException as e:
        print(f"[!] 下线请求失败: {e}")
        return False
    print(f"[*] 下线请求已发送 (HTTP {r2.status_code})")

    # 4. 等待断开生效(最多 8 秒)
    deadline = time.time() + 8
    while time.time() < deadline:
        if not check_online():
            print("[√] 已下线, 网络已断开")
            return True
        time.sleep(0.5)
    print("[!] 请求已被接受, 但设备仍在线(可能被网络自动重连)")
    return False


def capture_login(force: bool = False) -> dict:
    """供网页控制台调用: 执行认证并捕获文本输出"""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            if not force:
                if check_online():
                    print("[√] 已经在线, 无需登录")
                    return {"ok": True, "output": buf.getvalue().strip()}
                # 网页点击场景: 最多等 30 秒(避免按钮长时间无反馈)
                if not wait_network_ready(timeout_s=30):
                    print("[×] 未检测到校园网(检查网线/WiFi 是否已连接)")
                    return {"ok": False, "output": buf.getvalue().strip()}
            ok = fast_login(force)
    except SystemExit:
        ok = False
    except Exception as exc:
        print(f"[!] 认证异常: {exc}")
        ok = False
    return {"ok": bool(ok), "output": buf.getvalue().strip()}


# ================================================================
#  环境检测 / 开机自启
# ================================================================

def check_env() -> dict:
    """检测 Python 版本与依赖包"""
    packages = {}
    for module, pip_name in (("requests", "requests"),
                             ("Crypto", "pycryptodome")):
        try:
            r = subprocess.run([sys.executable, "-c", f"import {module}"],
                               capture_output=True, timeout=20)
            packages[pip_name] = r.returncode == 0
        except Exception:
            packages[pip_name] = False

    return {
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "packages": packages,
    }


# ---- 开机自启(按平台实现: Windows 快捷方式 / Linux XDG / macOS LaunchAgent) ----
_APPDATA = os.environ.get("APPDATA", "")
WIN_STARTUP_DIR = (Path(_APPDATA) / "Microsoft" / "Windows" / "Start Menu"
                   / "Programs" / "Startup") if _APPDATA else None
STARTUP_LNK = "campus-autologin.lnk"
LEGACY_STARTUP_FILES = ["campus-autologin.bat", "campus_login.bat"]
LINUX_AUTOSTART = Path.home() / ".config" / "autostart" / "campus-autologin.desktop"
MAC_AGENT = (Path.home() / "Library" / "LaunchAgents"
             / "com.campusnet.autologin.plist")


def _win_startup_paths():
    if WIN_STARTUP_DIR is None:
        return []
    return [WIN_STARTUP_DIR / name for name in [STARTUP_LNK] + LEGACY_STARTUP_FILES]


def _unix_startup_target():
    """Linux/macOS 的自启动条目路径; 其他系统返回 None"""
    if sys.platform == "darwin":
        return MAC_AGENT
    if sys.platform.startswith("linux"):
        return LINUX_AUTOSTART
    return None


def startup_enabled() -> bool:
    if sys.platform.startswith("win"):
        return any(p.exists() for p in _win_startup_paths())
    target = _unix_startup_target()
    return bool(target and target.exists())


def _set_startup_windows(enabled: bool):
    WIN_STARTUP_DIR.mkdir(parents=True, exist_ok=True)
    if enabled:
        runner = Path(sys.executable).with_name("pythonw.exe")
        if not runner.exists():
            runner = Path(sys.executable)
        lnk = WIN_STARTUP_DIR / STARTUP_LNK
        args = f'"{ROOT / "campus_net.py"}" --login'
        ps = (
            "$ws = New-Object -ComObject WScript.Shell; "
            f"$lnk = $ws.CreateShortcut('{lnk}'); "
            f"$lnk.TargetPath = '{runner}'; "
            f"$lnk.Arguments = '{args}'; "
            f"$lnk.WorkingDirectory = '{ROOT}'; "
            "$lnk.Save()"
        )
        encoded = base64.b64encode(ps.encode("utf-16-le")).decode()
        subprocess.run(["powershell", "-NoProfile", "-NonInteractive",
                        "-EncodedCommand", encoded],
                       check=True, capture_output=True, timeout=60)
        # 清理旧的 bat 启动项, 避免与新快捷方式重复执行
        for name in LEGACY_STARTUP_FILES:
            old = WIN_STARTUP_DIR / name
            if old.exists():
                old.unlink()
        return True, ""
    for path in _win_startup_paths():
        if path.exists():
            path.unlink()
    return True, ""


def set_startup(enabled: bool):
    """开启/关闭开机自动认证, 返回 (是否成功, 错误信息)

    Windows: 启动文件夹快捷方式(直接拉起 pythonw, 无窗口)
    Linux:   XDG autostart (~/.config/autostart/*.desktop)
    macOS:   LaunchAgent (~/Library/LaunchAgents/*.plist)
    """
    try:
        if sys.platform.startswith("win"):
            return _set_startup_windows(enabled)
        target = _unix_startup_target()
        if target is None:
            return False, f"暂不支持的系统: {sys.platform}"
        if enabled:
            target.parent.mkdir(parents=True, exist_ok=True)
            runner = sys.executable or "python3"
            script = ROOT / "campus_net.py"
            if sys.platform == "darwin":
                content = (
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                    '<plist version="1.0">\n<dict>\n'
                    '    <key>Label</key>\n'
                    '    <string>com.campusnet.autologin</string>\n'
                    '    <key>ProgramArguments</key>\n'
                    '    <array>\n'
                    f'        <string>{runner}</string>\n'
                    f'        <string>{script}</string>\n'
                    '        <string>--login</string>\n'
                    '    </array>\n'
                    '    <key>RunAtLoad</key>\n'
                    '    <true/>\n'
                    '</dict>\n</plist>\n'
                )
            else:
                content = (
                    "[Desktop Entry]\n"
                    "Type=Application\n"
                    "Name=Campus Net Autologin\n"
                    "Comment=Auto login for campus network\n"
                    f'Exec="{runner}" "{script}" --login\n'
                    "Terminal=false\n"
                    "X-GNOME-Autostart-enabled=true\n"
                )
            target.write_text(content, encoding="utf-8")
        else:
            if target.exists():
                target.unlink()
        return True, ""
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"操作失败: {exc}"


# ================================================================
#  网页控制台
# ================================================================

class _Tee:
    """把输出同时写到控制台和日志文件"""

    def __init__(self, *streams):
        self._streams = streams

    def write(self, data):
        for stream in self._streams:
            try:
                stream.write(data)
            except Exception:
                pass
        return len(data)

    def flush(self):
        for stream in self._streams:
            try:
                stream.flush()
            except Exception:
                pass


def setup_logging():
    """--login 模式: 输出写入 login.log; 无控制台(pythonw 静默运行)时仅写日志"""
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 100_000:
            log = LOG_FILE.open("w", encoding="utf-8")      # 超 100KB 自动截断
        else:
            log = LOG_FILE.open("a", encoding="utf-8")
    except OSError:
        return
    try:
        log.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n")
    except Exception:
        pass
    if sys.stdout is None:          # pythonw: 没有控制台
        sys.stdout = log
        sys.stderr = log
    else:                           # 有控制台: 双写
        sys.stdout = _Tee(sys.stdout, log)
        sys.stderr = _Tee(sys.stderr, log)


def check_network_online() -> bool:
    """供控制台状态显示使用(不依赖 requests, 装依赖前也能用)"""
    probe = get_config().get("probe_url") or DEFAULT_CONFIG["probe_url"]
    try:
        req = urllib.request.Request(probe, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 204
    except Exception:
        return False


PAGE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🎓</text></svg>">
<title>校园网自动登录</title>
<style>
  :root {
    --bg: #f5f7fb; --card: #fff; --ink: #1c2333; --muted: #7a839b;
    --accent: #3b6cf6; --accent-dark: #2c55cc; --ok: #14a05a;
    --err: #dc2626; --line: #e6eaf3; --radius: 13px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: "Segoe UI", "Microsoft YaHei", system-ui, sans-serif;
    background: var(--bg); color: var(--ink); padding: 40px 16px;
    min-height: 100vh;
  }
  .wrap { max-width: 560px; margin: 0 auto; }
  h1 { font-size: 20px; text-align: center; margin-bottom: 22px; font-weight: 700; }
  .card {
    background: var(--card); border: 1px solid var(--line); border-radius: var(--radius);
    padding: 20px; margin-bottom: 14px;
  }
  .status-row { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
  .status-row .label { font-size: 13px; color: var(--muted); }
  .badge {
    display: inline-flex; align-items: center; gap: 7px; font-size: 13.5px; font-weight: 600;
    padding: 6px 14px; border-radius: 999px; background: #eef2fb; color: var(--muted);
    cursor: pointer; user-select: none;
  }
  .badge.ok { background: #e6f7ee; color: var(--ok); }
  .badge.off { background: #fdecec; color: var(--err); }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
  .actions { display: flex; gap: 10px; flex-wrap: wrap; }
  button { font-family: inherit; }
  .btn {
    border: none; border-radius: 9px; padding: 11px 20px; font-size: 14px;
    font-weight: 600; cursor: pointer; transition: opacity .15s, transform .06s;
  }
  .btn:active { transform: scale(.98); }
  .btn[disabled] { opacity: .45; cursor: not-allowed; }
  .green { background: #14a05a; color: #fff; flex: 1; }
  .green:hover:not([disabled]) { background: #0f8248; }
  .blue { background: var(--accent); color: #fff; }
  .blue:hover:not([disabled]) { background: var(--accent-dark); }
  .ghost { background: #eef2fb; color: var(--accent); font-size: 13px; padding: 9px 16px; }
  .ghost:hover:not([disabled]) { background: #e2eafc; }
  label { display: block; font-size: 13px; font-weight: 600; margin: 14px 0 6px; }
  input[type=text], input[type=password] {
    width: 100%; padding: 10px 12px; border: 1.5px solid var(--line);
    border-radius: 9px; font-size: 14px; background: #fbfcff; color: var(--ink);
    outline: none; transition: border-color .15s, box-shadow .15s;
  }
  input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59,108,246,.12); }
  .pwd-wrap { position: relative; }
  .pwd-wrap input { padding-right: 44px; }
  .eye {
    position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
    border: none; background: none; cursor: pointer; font-size: 15px; padding: 6px;
    color: var(--muted); opacity: .75;
  }
  .saved { font-size: 12px; color: var(--ok); font-weight: 400; margin-left: 6px; }
  .hint { font-size: 12px; color: var(--muted); line-height: 1.7; margin-top: 8px; }
  details { margin-top: 16px; }
  summary {
    cursor: pointer; font-size: 13px; color: var(--muted); user-select: none;
    list-style: none; display: flex; align-items: center; gap: 6px;
  }
  summary::before { content: "▸"; transition: transform .15s; font-size: 11px; }
  details[open] summary::before { transform: rotate(90deg); }
  .adv-body { padding-top: 6px; border-top: 1px dashed var(--line); margin-top: 12px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 0 12px; }
  pre.out {
    background: #10182a; color: #c9d6f2; border-radius: 9px; padding: 13px;
    font-size: 12.5px; line-height: 1.7; max-height: 260px; overflow: auto;
    white-space: pre-wrap; word-break: break-all; display: none; margin-top: 14px;
    font-family: Consolas, "Courier New", monospace;
  }
  .chips { display: flex; flex-wrap: wrap; gap: 7px; }
  .chip {
    font-size: 12.5px; padding: 5px 11px; border-radius: 999px;
    background: #eef2fb; color: var(--muted); display: inline-flex; gap: 5px; align-items: center;
  }
  .chip.ok { background: #e6f7ee; color: var(--ok); }
  .chip.bad { background: #fdecec; color: var(--err); }
  .opt-row { display: flex; gap: 16px; flex-wrap: wrap; font-size: 13px; color: var(--muted); }
  .switch { position: relative; display: inline-block; width: 46px; height: 26px; flex-shrink: 0; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider {
    position: absolute; cursor: pointer; inset: 0; background: #cdd5e6;
    border-radius: 999px; transition: background .2s;
  }
  .slider:before {
    content: ""; position: absolute; height: 20px; width: 20px; left: 3px; bottom: 3px;
    background: #fff; border-radius: 50%; transition: transform .2s;
    box-shadow: 0 1px 3px rgba(0,0,0,.22);
  }
  .switch input:checked + .slider { background: #14a05a; }
  .switch input:checked + .slider:before { transform: translateX(20px); }
  .switch input:disabled + .slider { opacity: .5; cursor: not-allowed; }
  .foot { text-align: center; color: var(--muted); font-size: 12px; margin-top: 18px; line-height: 2; }
  .foot a { color: var(--muted); }
  #toast {
    position: fixed; top: 22px; left: 50%; transform: translateX(-50%) translateY(-70px);
    background: var(--ink); color: #fff; padding: 10px 20px; border-radius: 9px;
    font-size: 13.5px; transition: transform .25s; z-index: 99; max-width: 82vw;
    box-shadow: 0 8px 22px rgba(0,0,0,.16);
  }
  #toast.show { transform: translateX(-50%) translateY(0); }
</style>
</head>
<body>
<div class="wrap">
  <h1>🎓 校园网自动登录</h1>

  <!-- 连接控制 -->
  <div class="card">
    <div class="status-row">
      <span class="label">网络状态</span>
      <span class="badge" id="netBadge" onclick="refreshStatus()" title="点击刷新"><span class="dot"></span><span id="netText">检测中…</span></span>
    </div>
    <div class="actions">
      <button class="btn green" id="connectBtn" onclick="doConnect()">连接网络</button>
    </div>
    <pre class="out" id="output"></pre>
  </div>

  <!-- 账号配置 -->
  <div class="card">
    <label for="username">校园网账号</label>
    <input type="text" id="username" placeholder="学号 / 手机号 / 宽带账号" autocomplete="username">
    <label for="password">密码 <span class="saved" id="pwdSaved"></span></label>
    <div class="pwd-wrap">
      <input type="password" id="password" placeholder="登录密码" autocomplete="current-password">
      <button class="eye" type="button" onclick="togglePwd()" title="显示/隐藏密码">👁</button>
    </div>
    <div class="actions" style="margin-top:18px">
      <button class="btn blue" id="saveBtn" onclick="saveConfig()" style="flex:1">保存配置</button>
    </div>

    <details>
      <summary>高级设置</summary>
      <div class="adv-body">
        <label for="host">认证服务器地址</label>
        <input type="text" id="host" placeholder="http://110.184.24.61">
        <div class="grid2">
          <div>
            <label for="userip">userip（可选）</label>
            <input type="text" id="userip" placeholder="自动获取">
          </div>
          <div>
            <label for="nasip">nasip（可选）</label>
            <input type="text" id="nasip" placeholder="自动获取">
          </div>
        </div>
        <label for="mac">mac（本机网卡地址，可选）</label>
        <input type="text" id="mac" placeholder="例如 aa-bb-cc-dd-ee-ff">
        <label for="probe_url">联网探测地址</label>
        <input type="text" id="probe_url" placeholder="http://connect.rom.miui.com/generate_204">
        <div class="hint">网关参数留空即可（正常模式自动获取），仅排障时使用。</div>
        <label for="skipCheck" style="margin-top:16px">开机优化</label>
        <label style="display:flex;align-items:center;gap:8px;font-weight:normal;cursor:pointer">
          <input type="checkbox" id="skipCheck" style="width:auto">
          <span>跳过在线检测（开机约快 2 秒）</span>
        </label>
        <div class="hint">关闭（默认）：开机会先检测"是否已在线"（约 2 秒），任何网络环境下都处理得更稳。<br>
        开启后：开机少花约 2 秒；但若电脑有时用其他网络（如 Wi-Fi）上网，启动时会多等约 15 秒并在日志记录一次超时——只接校园网的话建议开启。</div>
        <div class="actions" style="margin-top:14px">
          <button class="btn ghost" id="forceBtn" onclick="doForceTest()">执行强制认证测试</button>
        </div>
        <pre class="out" id="advOutput"></pre>
      </div>
    </details>
  </div>

  <!-- 开机自动连接 -->
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:14px">
      <div>
        <div style="font-size:14px;font-weight:600">开机自动连接</div>
        <div class="hint" style="margin-top:5px" id="startupHint">加载中…</div>
      </div>
      <label class="switch">
        <input type="checkbox" id="startupToggle" onchange="toggleStartup()">
        <span class="slider"></span>
      </label>
    </div>
  </div>

  <!-- 运行环境 -->
  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <span style="font-size:13px;color:var(--muted)">运行环境</span>
      <span style="font-size:12px;color:var(--muted)" id="envSummary"></span>
    </div>
    <div class="chips" id="envChips"><span class="chip">检测中…</span></div>

    <div style="margin-top:16px">
      <div class="hint" id="installHint" style="margin:0 0 10px"></div>
      <div class="opt-row" style="margin:0 0 10px">
        <span style="font-size:12px">依赖默认通过清华镜像下载</span>
      </div>
      <button class="btn blue" id="installBtn" onclick="doInstall()">一键配置环境</button>
      <pre class="out" id="envOutput"></pre>
    </div>
  </div>

  <div class="foot">
    仅限本机访问 · 仅用于登录你本人拥有使用权的账号<br>
    <a href="#" onclick="shutdown(event)">关闭向导服务</a>
  </div>
</div>
<div id="toast"></div>
<script>
const $ = id => document.getElementById(id);
let busy = false;

function toast(msg, ok) {
  const t = $('toast');
  t.textContent = msg;
  t.style.background = ok === false ? '#dc2626' : '#1c2333';
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

function lockAll(on) {
  ['connectBtn', 'saveBtn', 'forceBtn', 'installBtn'].forEach(id => {
    const b = $(id);
    if (b) b.disabled = on;
  });
}

async function runAction(btnId, busyLabel, fn) {
  if (busy) return null;
  busy = true;
  const btn = $(btnId);
  const orig = btn.textContent;
  btn.textContent = busyLabel;
  lockAll(true);
  try {
    return await fn();
  } finally {
    btn.textContent = orig;
    busy = false;
    lockAll(false);
    refreshStatus();
  }
}

/* ---------------- 状态 ---------------- */

async function refreshStatus() {
  const badge = $('netBadge'), text = $('netText');
  badge.className = 'badge'; text.textContent = '检测中…';
  try {
    const d = await (await fetch('/api/status')).json();
    badge.className = 'badge ' + (d.online ? 'ok' : 'off');
    text.textContent = d.online ? '在线（已认证）' : '离线（未认证）';
    return d.online;
  } catch (e) { text.textContent = '检测失败'; return null; }
}

/* ---------------- 环境 ---------------- */

async function refreshEnv() {
  try {
    const d = await (await fetch('/api/env')).json();
    const chips = [];
    chips.push(chip(true, 'Python ' + d.python));
    const missingCore = [];
    for (const [name, ok] of Object.entries(d.packages)) {
      chips.push(chip(ok, name));
      if (!ok) missingCore.push(name);
    }

    $('envChips').innerHTML = chips.join('');
    $('envSummary').textContent = missingCore.length ? '⚠ 缺少依赖' : '✓ 就绪';
    $('installHint').textContent = missingCore.length
      ? '⚠ 缺少必要依赖：' + missingCore.join('、') + '，请点击下方按钮一键安装'
      : '环境已就绪；如需重装可再次执行';
    return d;
  } catch (e) {
    $('envChips').innerHTML = '<span class="chip bad">环境检测失败</span>';
    return null;
  }
}

function chip(ok, text) {
  return '<span class="chip ' + (ok ? 'ok' : 'bad') + '">' + (ok ? '✓' : '✕') + ' ' + text + '</span>';
}

async function ensureDeps() {
  const d = await refreshEnv();
  if (!d) return false;
  const missing = Object.entries(d.packages)
    .filter(([, ok]) => !ok).map(([k]) => k);
  if (missing.length) {
    toast('请先安装依赖: ' + missing.join('、'), false);
    $('envChips').scrollIntoView({ behavior: 'smooth', block: 'center' });
    return false;
  }
  return true;
}

/* ---------------- 操作 ---------------- */

async function saveConfig() {
  const body = {
    username: $('username').value.trim(),
    password: $('password').value,
    host: $('host').value.trim(),
    probe_url: $('probe_url').value.trim(),
    skip_online_check: $('skipCheck').checked,
    gateway: {
      userip: $('userip').value.trim(),
      nasip: $('nasip').value.trim(),
      mac: $('mac').value.trim(),
    }
  };
  const d = await (await fetch('/api/config', { method: 'POST', body: JSON.stringify(body) })).json();
  if (d.ok) {
    toast('配置已保存');
    $('password').value = '';
    $('pwdSaved').textContent = '（已保存，留空则不修改）';
  } else {
    toast(d.error || '保存失败', false);
  }
}

async function callApi(url, outEl) {
  const out = $(outEl);
  out.style.display = 'block';
  const d = await (await fetch(url, { method: 'POST', body: '{}' })).json();
  out.textContent = d.output || (d.ok ? '完成' : '失败');
  return d;
}

async function doConnect() {
  if (!(await ensureDeps())) return;
  await runAction('connectBtn', '连接中…', async () => {
    const d = await callApi('/api/connect', 'output');
    toast(d.ok ? '连接成功，网络已可用' : '连接未成功，请看输出', d.ok);
  });
}

async function doForceTest() {
  if (!(await ensureDeps())) return;
  await runAction('forceBtn', '测试中…', async () => {
    const d = await callApi('/api/test', 'advOutput');
    toast(d.ok ? '强制认证成功' : '认证未通过，请看输出', d.ok);
  });
}

async function doInstall() {
  await runAction('installBtn', '配置中…（约 1-3 分钟）', async () => {
    const d = await callApi('/api/install', 'envOutput');
    toast(d.ok ? '环境配置完成' : '安装失败，请看输出', d.ok);
    await refreshEnv();
  });
}

function togglePwd() {
  const p = $('password');
  p.type = p.type === 'password' ? 'text' : 'password';
}

/* ---------------- 开机自动连接 ---------------- */

async function refreshStartup() {
  try {
    const d = await (await fetch('/api/startup')).json();
    $('startupToggle').checked = !!d.enabled;
    $('startupHint').textContent = d.enabled
      ? '已开启：开机静默自动认证（无窗口，日志见 login.log）'
      : '已关闭：开机后需手动点击「连接网络」';
  } catch (e) {
    $('startupHint').textContent = '状态读取失败';
  }
}

async function toggleStartup() {
  const want = $('startupToggle').checked;
  $('startupToggle').disabled = true;
  try {
    const d = await (await fetch('/api/startup', {
      method: 'POST', body: JSON.stringify({ enabled: want })
    })).json();
    if (!d.ok) {
      $('startupToggle').checked = !want;
      toast(d.error || '设置失败', false);
    } else {
      toast(want ? '已开启开机自动连接' : '已关闭开机自动连接');
    }
  } catch (e) {
    $('startupToggle').checked = !want;
    toast('设置失败', false);
  }
  $('startupToggle').disabled = false;
  await refreshStartup();
}

async function shutdown(e) {
  e.preventDefault();
  if (!confirm('关闭向导服务？（已保存的配置不受影响）')) return;
  try { await fetch('/api/shutdown', { method: 'POST' }); } catch (err) {}
  document.body.innerHTML = '<div style="text-align:center;padding-top:120px;font-size:15px;color:#7a839b">'
    + '✓ 向导服务已关闭，可以关闭此页面了</div>';
}

/* ---------------- 初始化 ---------------- */

(async function init() {
  try {
    const cfg = await (await fetch('/api/config')).json();
    $('username').value = cfg.username || '';
    if (cfg.has_password) $('pwdSaved').textContent = '（已保存，留空则不修改）';
    $('host').value = cfg.host || '';
    $('probe_url').value = cfg.probe_url || '';
    $('userip').value = (cfg.gateway || {}).userip || '';
    $('nasip').value = (cfg.gateway || {}).nasip || '';
    $('mac').value = (cfg.gateway || {}).mac || '';
    $('skipCheck').checked = !!cfg.skip_online_check;
  } catch (e) { toast('加载配置失败', false); }
  refreshStatus();
  refreshEnv();
  refreshStartup();
})();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # 静默, 不刷控制台

    def _check_host(self) -> bool:
        """仅接受本机访问, 防 DNS 重绑定"""
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]")
        if host not in ("127.0.0.1", "localhost", "::1"):
            self._send_json({"ok": False, "error": "非法访问来源"}, 403)
            return False
        return True

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------ GET

    def do_GET(self):
        if not self._check_host():
            return
        if self.path == "/" or self.path.startswith("/index"):
            body = PAGE_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/config":
            cfg = get_config()
            self._send_json({
                "username": cfg.get("username", ""),
                "has_password": bool(cfg.get("password")),
                "host": cfg.get("host", ""),
                "probe_url": cfg.get("probe_url", ""),
                "skip_online_check": bool(cfg.get("skip_online_check")),
                "gateway": cfg.get("gateway", {}),
            })
        elif self.path == "/api/status":
            self._send_json({"online": check_network_online()})
        elif self.path == "/api/env":
            self._send_json(check_env())
        elif self.path == "/api/startup":
            self._send_json({"enabled": startup_enabled()})
        else:
            self.send_error(404)

    # ------------------------------------------------------------ POST

    def do_POST(self):
        if not self._check_host():
            return
        if self.path == "/api/shutdown":
            self._send_json({"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            self._send_json({"ok": False, "error": "请求格式错误"}, 400)
            return

        if self.path == "/api/config":
            self._handle_save(payload)
        elif self.path == "/api/install":
            self._handle_install()
        elif self.path == "/api/connect":
            self._send_json(capture_login(force=False))
        elif self.path == "/api/test":
            self._send_json(capture_login(force=True))
        elif self.path == "/api/startup":
            success, error = set_startup(bool(payload.get("enabled")))
            self._send_json({"ok": success} if success else {"ok": False, "error": error})
        else:
            self.send_error(404)

    # ------------------------------------------------------------ 具体处理

    def _handle_save(self, payload: dict):
        current = get_config()
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        if not username:
            self._send_json({"ok": False, "error": "账号不能为空"})
            return
        if password:
            current["password"] = password
        elif not current.get("password"):
            self._send_json({"ok": False, "error": "密码不能为空"})
            return

        current["username"] = username
        current["host"] = (payload.get("host") or "").strip() or DEFAULT_CONFIG["host"]
        current["probe_url"] = (payload.get("probe_url") or "").strip() or DEFAULT_CONFIG["probe_url"]
        current["skip_online_check"] = bool(payload.get("skip_online_check"))
        gateway = payload.get("gateway") or {}
        current["gateway"] = {
            "userip": (gateway.get("userip") or "").strip(),
            "nasip": (gateway.get("nasip") or "").strip(),
            "mac": (gateway.get("mac") or "").strip(),
        }
        try:
            CONFIG_FILE.write_text(json.dumps(current, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
        except OSError as exc:
            self._send_json({"ok": False, "error": f"写入失败: {exc}"})
            return
        reload_config()
        self._send_json({"ok": True})

    def _handle_install(self):
        cmd = [sys.executable, "-m", "pip", "install",
               "-r", "requirements.txt", "-i", MIRROR_URL]
        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
        try:
            proc = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True,
                                  text=True, encoding="utf-8", errors="replace", timeout=600)
            output = ((proc.stdout or "") + (proc.stderr or "")).strip()
            self._send_json({"ok": proc.returncode == 0, "output": output})
        except subprocess.TimeoutExpired:
            self._send_json({"ok": False, "output": "安装超时（10 分钟），请检查网络后重试"})
        except OSError as exc:
            self._send_json({"ok": False, "output": f"无法启动 pip: {exc}"})


def pick_port(start: int = 8765, tries: int = 12) -> int:
    import socket
    for port in range(start, start + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
    return 0  # 交给系统随机分配


def run_console():
    port = pick_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{server.server_address[1]}/"

    print("=" * 52)
    print("  校园网自动登录 · 控制台")
    print("=" * 52)
    print(f"  控制台地址: {url}")
    print("  浏览器将自动打开, 完成后在页面底部点击「关闭向导服务」")
    print("  (若浏览器未自动打开, 请手动复制上面的地址访问)")
    print("=" * 52)

    if os.environ.get("NO_BROWSER") != "1":
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n控制台已退出")


def main():
    if "--logout" in sys.argv:
        setup_logging()
        print("[*] 正在下线...")
        try:
            ok = fast_logout()
        except Exception as exc:
            print(f"[!] 下线异常: {exc}")
            ok = False
        if not ok:
            print("[×] 下线未成功")
        return

    if "--login" in sys.argv or "--force" in sys.argv:
        force = "--force" in sys.argv
        setup_logging()
        if not force:
            # 开机场景: 网络未就绪时探测请求可能被 DNS/网关拖住数秒, 用短超时快速失败,
            # 随后由"等待网络就绪"循环接管(短超时+密集轮询, 网络一通立即继续认证)
            # 用户在控制台开启了"跳过在线检测"(开机优化)时, 直接进入就绪等待与认证
            if get_config().get("skip_online_check"):
                print("[*] 已按设置跳过在线检测(开机优化)")
            else:
                print("[*] 检测网络状态...")
                t_phase = time.time()
                if check_online(timeout=3):
                    print("[√] 已经在线, 无需登录")
                    return
                print(f"[i] 在线检测用时 {time.time() - t_phase:.1f} 秒")
            t_phase = time.time()
            if not wait_network_ready():
                print("[×] 等待网络就绪超时, 请检查网线/WiFi 是否已连接校园网")
                return
            print(f"[i] 网络就绪用时 {time.time() - t_phase:.1f} 秒")
        username = get_config(strict=True).get("username", "")
        t0 = time.time()
        print(f"[*] 开始认证 (账号 {username})...")
        try:
            ok = fast_login(force)
        except Exception as exc:
            print(f"[!] 认证异常: {exc}")
            ok = False
        if ok:
            print(f"[√] 认证完成, 网络已连接! (耗时 {time.time()-t0:.1f} 秒)")
        else:
            print("[×] 认证失败, 请检查账号密码或网络状态")
        return

    run_console()


if __name__ == "__main__":
    main()
