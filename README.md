# OpenClaw Security Scanner

[中文](#中文) | [English](#english)

---

## 中文

### 功能特性

- ✅ 30+ 项安全检测
- ✅ 支持本地/云端部署检测
- ✅ 后门/木马/可疑代码检测
- ✅ 安全漏洞扫描
- ✅ 一键自动修复
- ✅ JSON 格式输出
- ✅ 风险评分

### 安装

```bash
# 方式1: 直接运行
node ~/.openclaw/workspace/tools/security-scan/security-scan.js

# 方式2: 使用可执行文件
~/.openclaw/workspace/tools/security-scan/security-scan

# 方式3: 添加到 PATH
echo 'export PATH="$HOME/.openclaw/workspace/tools/security-scan:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### 使用方法

```bash
# 检测所有安全问题
security-scan

# 检测并自动修复
security-scan --fix

# JSON 格式输出
security-scan --json

# 指定 OpenClaw 目录（用于远程检测）
security-scan --path=/path/to/.openclaw

# 只检测指定类别
security-scan --category=config
security-scan --category=network
security-scan --category=malware
security-scan --category=vulnerability

# 列出所有检测类别
security-scan --list

# 详细输出
security-scan --verbose

# 帮助
security-scan --help
```

### 检测项目

| 类别 | 检测项 |
|------|--------|
| 配置安全 | 配置文件权限、明文 Token、Token 强度、备份文件 |
| 网络安全 | 网关绑定地址、TLS 加密、开放端口、CORS 策略 |
| 认证安全 | Token 过期时间、双因素认证、登录尝试限制 |
| 插件安全 | 插件白名单、目录权限、未授权插件 |
| 会话安全 | 会话目录权限、会话文件权限、孤立文件 |
| 文件系统 | Workspace 权限、敏感文件、根目录权限 |
| 沙箱安全 | 命令执行策略、浏览器控制、设备节点访问 |
| 云端部署 | 容器用户、环境变量、日志级别 |
| 后门/木马 | 可疑文件扫描、可疑代码检测、网络连接检查 |
| 安全漏洞 | OpenClaw 版本、Node 版本、依赖包漏洞、配置漏洞 |

### 输出示例

```
🛡️  OpenClaw Security Scanner

📍 OpenClaw 目录: /Users/xxx/.openclaw
🖥️  部署类型: local
📦 版本: 2026.3.1

──────────────────────────────────────────────────

📊 检测结果:
   ✅ 通过: 18
   ❌ 失败: 2
   ⚠️  警告: 4
   🎯 风险分数: 75/100

❌ 需要修复的问题 (2):

  🔴 [critical] 配置文件权限
     配置文件权限过于宽松
     修复: chmod 600 "/Users/xxx/.openclaw/openclaw.json"

  🟠 [high] 插件白名单
     未配置插件白名单
     修复: openclaw config set plugins.allow ["feishu"]
```

### 自动修复

运行 `security-scan --fix` 自动修复以下问题：
- 配置文件权限设置为 600
- 会话目录权限设置为 700
- 删除备份文件
- 清理孤立会话文件

需要手动处理的问题会给出具体命令建议。

### 打包发布

```bash
# macOS ARM64 (M系列)
pkg security-scan.js --targets node18-darwin-arm64 --output security-scan

# macOS Intel
pkg security-scan.js --targets node18-darwin-x64 --output security-scan

# Linux
pkg security-scan.js --targets node18-linux-x64 --output security-scan

# Windows
pkg security-scan.js --targets node18-win-x64 --output security-scan.exe
```

### 开箱即用

这个工具是独立的，不需要安装任何依赖，直接用 Node.js 或可执行文件运行即可。可以分发给其他用户使用。

---

## English

### Features

- ✅ 30+ security checks
- ✅ Local/Cloud deployment detection
- ✅ Backdoor/Trojan/Suspicious code detection
- ✅ Security vulnerability scanning
- ✅ One-click auto-fix
- ✅ JSON output
- ✅ Risk scoring

### Installation

```bash
# Option 1: Run directly
node ~/.openclaw/workspace/tools/security-scan/security-scan.js

# Option 2: Use executable
~/.openclaw/workspace/tools/security-scan/security-scan

# Option 3: Add to PATH
echo 'export PATH="$HOME/.openclaw/workspace/tools/security-scan:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Usage

```bash
# Scan all security issues
security-scan

# Scan and auto-fix
security-scan --fix

# JSON output
security-scan --json

# Specify OpenClaw directory (for remote scanning)
security-scan --path=/path/to/.openclaw

# Scan specific category
security-scan --category=config
security-scan --category=network
security-scan --category=malware
security-scan --category=vulnerability

# List all categories
security-scan --list

# Verbose output
security-scan --verbose

# Help
security-scan --help
```

### Detection Items

| Category | Checks |
|----------|--------|
| Config Security | File permissions, Hardcoded tokens, Token strength, Backup files |
| Network Security | Bind address, TLS, Open ports, CORS policy |
| Auth Security | Token expiry, 2FA, Login attempt limits |
| Plugin Security | Plugin allowlist, Directory permissions, Unauthorized plugins |
| Session Security | Session dir permissions, File permissions, Orphaned files |
| Filesystem | Workspace permissions, Sensitive files, Root directory |
| Sandbox Security | Exec policy, Browser control, Device access |
| Cloud Deployment | Container user, Env secrets, Log level |
| Malware | Suspicious files, Suspicious code, Network connections |
| Vulnerabilities | OpenClaw version, Node version, Dep vulnerabilities, Config issues |

### Output Example

```
🛡️  OpenClaw Security Scanner

📍 OpenClaw directory: /Users/xxx/.openclaw
🖥️  Deployment: local
📦 Version: 2026.3.1

──────────────────────────────────────────────────

📊 Results:
   ✅ Passed: 18
   ❌ Failed: 2
   ⚠️  Warnings: 4
   🎯 Risk Score: 75/100

❌ Issues to fix (2):

  🔴 [critical] Config file permissions
     Config file is group/world readable
     Fix: chmod 600 "/Users/xxx/.openclaw/openclaw.json"

  🟠 [high] Plugin allowlist
     No plugin allowlist configured
     Fix: openclaw config set plugins.allow ["feishu"]
```

### Auto-Fix

Running `security-scan --fix` will automatically fix:
- Config file permissions to 600
- Session directory permissions to 700
- Delete backup files
- Clean orphaned session files

Issues requiring manual handling will show specific command suggestions.

### Build for Distribution

```bash
# macOS ARM64 (M series)
pkg security-scan.js --targets node18-darwin-arm64 --output security-scan

# macOS Intel
pkg security-scan.js --targets node18-darwin-x64 --output security-scan

# Linux
pkg security-scan.js --targets node18-linux-x64 --output security-scan

# Windows
pkg security-scan.js --targets node18-win-x64 --output security-scan.exe
```

### Ready to Use

This tool is standalone - no dependencies required. Just run with Node.js or the executable. Can be distributed to other users.
