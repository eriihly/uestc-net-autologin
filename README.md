# 电子科技大学电信校园网自动登录

点击code，downloadzip，解压文件夹后运行start文件，根据提示操作

> ⚠️ **适配说明**：本项目针对作者所在学校的认证系统开发（认证服务器 `110.184.24.61`）。
> 同体系的其他学校可直接使用（在配置向导的「高级设置」中修改服务器地址）；
> 不同认证系统的学校需要自行适配代码，欢迎提 Issue 交流。

## 功能特性

- **秒级认证**：复刻登录流程为纯 HTTP 请求，无需打开浏览器
- **单文件应用**：`campus_net.py` 一个文件搞定全部功能（网页控制台 + 命令行）
- **开机自启**：控制台开关一键配置（Windows / Linux / macOS 均支持），联网无需等待
- **不含任何个人信息**：账号密码保存在本地 `config.json`（已被 `.gitignore` 排除）

## 快速开始

### 1. 环境准备

**只需要一个运行时：Python 3.9+**（推荐 3.10~3.13；Windows 安装时请勾选 *Add Python to PATH*）。

```bash
pip install -r requirements.txt
```

国内网络建议加清华镜像：

```bash
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
```

依赖仅两个：`requests`（HTTP 请求）+ `pycryptodome`（密码加密）。



### 2. 打开控制台（推荐）

```bash
python campus_net.py     # 或双击 start.bat（Windows）/ 双击 start.command（macOS）/ 运行 ./start.sh（Linux）
```

浏览器会自动打开可视化控制台，所有操作都在这里完成：

| 功能 | 说明 |
|---|---|
| 📦 **一键配置环境** | 无需手敲 pip 命令，默认使用清华镜像 |
| 🔍 **环境自检** | Python 版本与依赖包逐项检查 |
| 📝 **账号配置** | 填表保存到本机 `config.json` |
| 🚀 **开机自动连接** | 网页开关一键配置 / 取消开机自启 |
| ⚙️ **开机优化** | 高级设置中可跳过在线检测（开机约快 2 秒，按需选择） |
| ⚡ **连接网络** | 等价于运行登录脚本，输出实时回显 |
| 🛠 **强制认证测试** | 完整执行一次认证流程，用于排障 |

> 控制台本身零依赖，所以可以先打开它、用「一键配置环境」装好依赖，再点「连接网络」，全程不用碰命令行。

也可以不用控制台：手动复制 `config.example.json` 为 `config.json` 填写，然后走下面的命令行方式。

### 3. 命令行使用（可选）

```bash
python campus_net.py --login     # 无界面：检测未认证时自动登录
python campus_net.py --force     # 强制走一遍完整认证（排障用）
python campus_net.py --logout    # 下线：断开当前认证（测试/临时使用）
```

Windows 用户可直接双击 `start.bat`；macOS 用户在访达中双击 `start.command`；Linux 运行 `./start.sh`（或各平台直接 `python3 campus_net.py`）。认证与控制台功能各平台完全一致。

> **🍎 macOS 用户必读**：从浏览器下载的 ZIP，首次双击 `start.command` 会被系统拦截（提示"Apple 无法验证…"）——这是 macOS 对所有未签名下载文件的保护机制（不是误报病毒），**处理一次即可**，二选一：
>
> - **方式 A（纯鼠标，不碰终端）**：双击被拦截后先点「完成」→ 打开「**系统设置 → 隐私与安全性**」→ 往下拉到「安全性」区域 → 点「**仍要打开**」→ 输入开机密码 → 再次双击 `start.command` 即可
> - **方式 B（终端一行命令）**：打开「终端」，把下面**整行**复制粘贴后回车（路径改成你的解压位置；小技巧：先输入 `cd ` 再把文件夹拖进终端窗口，路径会自动补全）：
>   ```bash
>   cd ~/Downloads/campus-net-autologin && chmod +x start.command start.sh && xattr -d com.apple.quarantine start.command && ./start.command
>   ```

### 4. 开机自动认证（可选）

**推荐**：在控制台打开「开机自动连接」开关，一键完成（可随时关闭）。各平台均使用系统原生机制、无需管理员权限：Windows 写启动文件夹快捷方式；Linux 写 XDG autostart（`~/.config/autostart/`）；macOS 写 LaunchAgent（`~/Library/LaunchAgents/`）。

开启后：开机认证**静默运行**（不弹任何窗口），运行日志写入项目目录下的 `login.log`（超 100KB 自动截断），排查问题时可直接查看。

Windows 也可以手动配置：在启动文件夹（`Win + R` 输入 `shell:startup`）新建一个指向 `pythonw.exe` 的快捷方式，参数填 `campus_net.py --login`（相比批处理，快捷方式开机运行不会闪现命令行窗口）。

开机后脚本会自动等待网络就绪并完成认证（内置重试与等待逻辑）。

## 工作原理（简述）

认证流程涉及多级跳转，本工具完整复刻了这条链路：

```
探测地址被网关劫持
  → /eportal/index.jsp（生成会话 sessionId）
  → /portal/portal-main → /portal/entry/pc/terminalLoad
  → /cas-sso/login?flowSessionId=...（iframe 中的登录表单）
  → AES-128-ECB 加密密码后提交（密钥来自页面的 login-croypto）
  → 302 获取 CAS 票据 → 完成门户流程（workFlow → userOnline）
  → 网络放行
```


## 常见问题

| 问题 | 处理 |
|---|---|
| 提示「未从跳转链中拿到 sessionId」 | 确认已连接校园网；若已认证会提示「已经在线」属正常 |
| 认证失败 | 请检查账号密码与网络状态；若学校改版认证页面，需更新脚本适配 |
| `--force` 模式失败 | 网关参数（userip/nasip/mac）已过期，在配置向导中更新（正常模式无需这些参数） |
| 电脑开了代理/VPN | 会干扰认证检测，使用前请关闭 |
| 换了学校/认证系统 | 在配置向导高级设置中修改服务器地址；若接口结构不同需改代码 |
| macOS 提示「Apple 无法验证 start.command」 | 这是系统对下载文件的隔离保护。终端执行 `xattr -d com.apple.quarantine start.command`，或在 系统设置 → 隐私与安全性 → 安全性 中点「仍要打开」 |

## 安全与隐私

- 账号密码仅保存在本机 `config.json`，**该文件已被 `.gitignore` 排除**，不会进入版本库
- 配置向导的网页服务只监听 `127.0.0.1`，局域网其他设备无法访问
- 密码在提交时按页面规则本地 AES 加密，与浏览器登录行为一致
- 本工具不收集、不上传任何数据

## 免责声明

本项目仅供学习交流与个人自动化使用，请在你拥有合法使用权的账号与网络环境下使用。
使用前请确认符合所在学校与运营商的网络使用规定，因使用本项目产生的一切后果由使用者自行承担。

## License

[MIT](LICENSE)
