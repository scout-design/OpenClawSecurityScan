#!/bin/bash
# OpenClaw Security Scanner - 一键安装脚本

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$HOME/.openclaw/tools"

# 创建工具目录
mkdir -p "$TOOLS_DIR"

# 复制脚本
cp -r "$SCRIPT_DIR" "$TOOLS_DIR/security-scan"

# 创建符号链接
mkdir -p "$HOME/.local/bin"
ln -sf "$TOOLS_DIR/security-scan/security-scan.js" "$HOME/.local/bin/security-scan"
chmod +x "$TOOLS_DIR/security-scan/security-scan.js"

# 添加到 PATH (如果 .zshrc 中没有)
if ! grep -q "HOME/.local/bin" "$HOME/.zshrc" 2>/dev/null; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
fi

echo "✅ 安装完成!"
echo ""
echo "使用方法:"
echo "  security-scan              # 检测安全问题"
echo "  security-scan --fix        # 检测并自动修复"
echo "  security-scan --json      # JSON 格式输出"
echo "  security-scan --list      # 列出所有检测项"
echo ""
echo "或者直接运行:"
echo "  node $TOOLS_DIR/security-scan/security-scan.js"
