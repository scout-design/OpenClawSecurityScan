#!/usr/bin/env node

/**
 * OpenClaw Security Scanner CLI
 * 
 * 检测 OpenClaw 部署的安全问题，支持一键修复
 * 
 * 用法:
 *   security-scan                    # 检测所有安全问题
 *   security-scan --fix             # 检测并自动修复
 *   security-scan --json            # JSON 格式输出
 *   security-scan --path=/custom    # 指定 OpenClaw 目录
 *   security-scan --category=config # 只检测配置安全
 *   security-scan --list            # 列出所有检测项
 */

const { readFileSync, statSync, readdirSync, existsSync, writeFileSync, chmodSync } = require('fs');
const { join, dirname } = require('path');
const { homedir } = require('os');
const { execSync } = require('child_process');

// ============================================================================
// 命令行参数解析
// ============================================================================

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    path: null,
    fix: false,
    json: false,
    list: false,
    verbose: false,
    help: false,
    category: null,
  };
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--path' || arg === '-p') {
      options.path = args[++i];
    } else if (arg.startsWith('--path=')) {
      options.path = arg.split('=')[1];
    } else if (arg === '--fix' || arg === '-f') {
      options.fix = true;
    } else if (arg === '--json' || arg === '-j') {
      options.json = true;
    } else if (arg === '--list' || arg === '-l') {
      options.list = true;
    } else if (arg === '--verbose' || arg === '-v') {
      options.verbose = true;
    } else if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg.startsWith('--category=')) {
      options.category = arg.split('=')[1];
    } else if (arg === '--category' || arg === '-c') {
      options.category = args[++i];
    }
  }
  
  return options;
}

const args = parseArgs();

// ============================================================================
// 配置路径（支持自定义）
// ============================================================================

const DEFAULT_OPENCLAW_PATH = join(homedir(), '.openclaw');
const OPENCLAW_PATH = args.path || DEFAULT_OPENCLAW_PATH;
const CONFIG_FILE = join(OPENCLAW_PATH, 'openclaw.json');
const SESSIONS_DIR = join(OPENCLAW_PATH, 'agents', 'main', 'sessions');
const EXTENSIONS_DIR = join(OPENCLAW_PATH, 'extensions');
const WORKSPACE_DIR = join(OPENCLAW_PATH, 'workspace');

// ============================================================================
// 检测类别和描述
// ============================================================================

const CATEGORIES = {
  config: '配置安全',
  network: '网络安全',
  auth: '认证安全',
  plugin: '插件安全',
  session: '会话安全',
  filesystem: '文件系统',
  sandbox: '沙箱安全',
  cloud: '云端部署',
  malware: '后门/木马',
  vulnerability: '安全漏洞',
};

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// ============================================================================
// 工具函数
// ============================================================================

function getOpenClawVersion() {
  try {
    return execSync('openclaw --version 2>/dev/null || echo "unknown"', { encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

function detectDeploymentType() {
  const cloudIndicators = [
    process.env.KUBERNETES_SERVICE_HOST,
    process.env.DOCKER_CONTAINER,
    process.env.AWS_LAMBIA_FUNCTION_NAME,
    process.env.VERCEL,
    process.env.RENDER,
    process.env.CLOUD_RUN_JOB,
  ];
  return cloudIndicators.some(Boolean) ? 'cloud' : 'local';
}

function getFilePermissions(path) {
  try {
    const stat = statSync(path);
    const mode = stat.mode;
    return (mode & parseInt('777', 8)).toString(8);
  } catch {
    return 'N/A';
  }
}

function isFileReadableByOthers(path) {
  try {
    const stat = statSync(path);
    const mode = stat.mode;
    // Check group/other read bits
    return (mode & parseInt('044', 8)) !== 0;
  } catch {
    return false;
  }
}

function loadConfig() {
  try {
    if (existsSync(CONFIG_FILE)) {
      const content = readFileSync(CONFIG_FILE, 'utf8');
      return JSON.parse(content);
    }
  } catch {
    // Ignore
  }
  return null;
}

function checkPortListening() {
  try {
    const output = execSync('lsof -i -P -n 2>/dev/null | grep LISTEN || ss -tlnp 2>/dev/null | grep -v State', { encoding: 'utf8' });
    const lines = output.split('\n').filter(l => l.includes('node') || l.includes('openclaw'));
    return lines.map(line => {
      const parts = line.split(/\s+/);
      const portPart = parts.find(p => p.includes(':'))?.split(':').pop();
      return {
        port: parseInt(portPart || '0'),
        address: '0.0.0.0',
        process: parts[0] || 'unknown',
      };
    }).filter(p => p.port > 0);
  } catch {
    return [];
  }
}

// ============================================================================
// 检测模块
// ============================================================================

// 1. 配置安全检测
async function checkConfigSecurity() {
  const results = [];
  const config = loadConfig();

  // 1.1 配置文件权限
  const configPerms = getFilePermissions(CONFIG_FILE);
  results.push({
    id: 'config:permissions',
    category: 'config',
    check: '配置文件权限',
    status: configPerms === '600' || configPerms === '400' ? 'pass' : 'fail',
    severity: 'critical',
    message: configPerms === '600' || configPerms === '400' 
      ? '配置文件权限正确' 
      : '配置文件权限过于宽松',
    current: configPerms,
    expected: '600 或 400',
    fixCommand: '设置配置文件为 600 权限',
    fixCommand: `chmod 600 "${CONFIG_FILE}"`,
  });

  // 1.2 Token 硬编码检测
  const hardcodedTokens = [];
  if (config) {
    const tokenFields = ['token', 'apiKey', 'api_key', 'secret', 'password', 'accessToken'];
    for (const field of tokenFields) {
      if (config[field] && typeof config[field] === 'string' && 
          config[field].length > 10 && 
          !config[field].startsWith('env:')) {
        hardcodedTokens.push(field);
      }
    }
  }
  results.push({
    id: 'config:hardcoded-tokens',
    category: 'config',
    check: '明文 Token 检测',
    status: hardcodedTokens.length === 0 ? 'pass' : 'fail',
    severity: 'high',
    message: hardcodedTokens.length === 0 
      ? '未发现明文 Token' 
      : `发现明文 Token 字段: ${hardcodedTokens.join(', ')}`,
    fixCommand: '将 Token 迁移到环境变量（env:VAR_NAME）',
  });

  // 1.3 Gateway Token 强度
  const gatewayToken = config?.gateway?.token || config?.token;
  const tokenLength = gatewayToken ? String(gatewayToken).length : 0;
  results.push({
    id: 'config:token-strength',
    category: 'config',
    check: 'Gateway Token 强度',
    status: tokenLength >= 32 ? 'pass' : tokenLength > 0 ? 'warning' : 'fail',
    severity: 'high',
    message: tokenLength >= 32 
      ? 'Token 长度足够' 
      : tokenLength > 0 
        ? 'Token 长度偏短，建议32位以上'
        : '未配置 Gateway Token\n     手动修复: openclaw configure',
    current: tokenLength > 0 ? `${tokenLength} 字符` : '未设置',
    expected: '32 字符以上',
    // Gateway Token 需要手动配置，无自动修复命令
    fixCommand: undefined,
  });

  // 1.4 备份配置检测
  const backupFiles = ['openclaw.json.bak', 'openclaw.json.backup', '.openclaw.json'];
  const foundBackups = backupFiles.filter(f => existsSync(join(OPENCLAW_PATH, f)));
  results.push({
    id: 'config:backup-files',
    category: 'config',
    check: '配置文件备份',
    status: foundBackups.length === 0 ? 'pass' : 'warning',
    severity: 'medium',
    message: foundBackups.length === 0 
      ? '未发现备份文件' 
      : `发现备份文件: ${foundBackups.join(', ')}`,
    fixCommand: foundBackups.length > 0 ? `rm -f ${foundBackups.map(f => `"${join(OPENCLAW_PATH, f)}"`).join(' ')}` : undefined,
  });

  return results;
}

// 2. 网络安全检测
async function checkNetworkSecurity() {
  const results = [];
  const config = loadConfig();

  // 2.1 网关绑定地址
  const bindAddress = config?.gateway?.bind || config?.bind || '127.0.0.1';
  const deployment = detectDeploymentType();
  const isExposed = bindAddress === '0.0.0.0';
  const hasTLS = config?.gateway?.tls || config?.tls;
  
  if (deployment === 'local') {
    results.push({
      id: 'network:bind-address',
      category: 'network',
      check: '网关绑定地址',
      status: bindAddress === '127.0.0.1' ? 'pass' : isExposed ? 'warning' : 'pass',
      severity: isExposed && !hasTLS ? 'critical' : 'medium',
      message: bindAddress === '127.0.0.1' 
        ? '本地部署绑定正确'
        : isExposed 
          ? (hasTLS ? '绑定0.0.0.0但已启用TLS' : '绑定0.0.0.0且未启用TLS，存在安全风险')
          : `绑定地址: ${bindAddress}`,
      current: bindAddress,
      expected: '127.0.0.1 (本地) 或 0.0.0.0 + TLS (云端)',
      fixCommand: hasTLS ? undefined : `openclaw config set gateway.bind "127.0.0.1"`,
    });
  }

  // 2.2 TLS 配置
  results.push({
    id: 'network:tls',
    category: 'network',
    check: 'TLS 加密传输',
    status: hasTLS ? 'pass' : deployment === 'cloud' ? 'fail' : 'info',
    severity: deployment === 'cloud' ? 'critical' : 'low',
    message: hasTLS 
      ? '已启用 TLS 加密' 
      : deployment === 'cloud' 
        ? '云端部署未启用 TLS' 
        : '本地部署不需要 TLS',
    fixCommand: deployment === 'cloud' ? '配置 SSL 证书' : undefined,
  });

  // 2.3 端口检测
  const ports = checkPortListening();
  const gatewayPort = config?.gateway?.port || config?.port || 8080;
  const exposedPorts = ports.filter(p => 
    p.address === '0.0.0.0' && p.port !== 22 && p.port !== 80 && p.port !== 443
  );
  
  results.push({
    id: 'network:ports',
    category: 'network',
    check: '开放端口检测',
    status: exposedPorts.length === 0 ? 'pass' : 'warning',
    severity: 'medium',
    message: exposedPorts.length === 0 
      ? '未发现异常开放端口' 
      : `发现开放端口: ${exposedPorts.map(p => `${p.port}(${p.process})`).join(', ')}`,
  });

  // 2.4 CORS 配置
  const corsOrigin = config?.gateway?.cors?.origin || config?.cors?.origin;
  results.push({
    id: 'network:cors',
    category: 'network',
    check: 'CORS 跨域策略',
    status: !corsOrigin ? 'info' : corsOrigin === '*' ? 'fail' : 'pass',
    severity: !corsOrigin ? 'low' : corsOrigin === '*' ? 'high' : 'low',
    message: !corsOrigin 
      ? '未配置 CORS（使用默认值）' 
      : corsOrigin === '*' 
        ? 'CORS 允许所有来源，风险较高'
        : `CORS 已限制为: ${corsOrigin}`,
    fixCommand: corsOrigin === '*' ? '限制 CORS 到特定域名' : undefined,
  });

  return results;
}

// 3. 认证安全检测
async function checkAuthSecurity() {
  const results = [];
  const config = loadConfig();

  // 3.1 Token 过期时间
  const tokenExpiry = config?.gateway?.tokenExpiry || config?.tokenExpiry;
  results.push({
    id: 'auth:token-expiry',
    category: 'auth',
    check: 'Token 过期时间',
    status: !tokenExpiry || tokenExpiry === 0 ? 'warning' : 'pass',
    severity: 'medium',
    message: !tokenExpiry || tokenExpiry === 0 
      ? 'Token 未设置过期时间（建议设置）' 
      : `Token 过期时间: ${tokenExpiry}天`,
    fixCommand: !tokenExpiry ? 'openclaw config set gateway.tokenExpiry 30' : undefined,
  });

  // 3.2 2FA 配置
  const has2FA = config?.security?.twoFactorAuth || config?.twoFactorAuth;
  results.push({
    id: 'auth:2fa',
    category: 'auth',
    check: '双因素认证',
    status: has2FA ? 'pass' : 'warning',
    severity: 'medium',
    message: has2FA 
      ? '已启用双因素认证' 
      : '未启用双因素认证（建议启用）',
    fixCommand: !has2FA ? 'openclaw config set security.twoFactorAuth true' : undefined,
  });

  // 3.3 登录尝试限制
  const maxAttempts = config?.security?.maxLoginAttempts || config?.maxLoginAttempts;
  results.push({
    id: 'auth:login-attempts',
    category: 'auth',
    check: '登录尝试限制',
    status: maxAttempts && maxAttempts <= 5 ? 'pass' : 'warning',
    severity: 'low',
    message: maxAttempts && maxAttempts <= 5 
      ? `登录尝试限制: ${maxAttempts}次` 
      : '未配置登录尝试限制（建议设置为5次）',
    fixCommand: !maxAttempts ? 'openclaw config set security.maxLoginAttempts 5' : undefined,
  });

  return results;
}

// 4. 插件安全检测
async function checkPluginSecurity() {
  const results = [];
  const config = loadConfig();

  // 4.1 插件白名单
  const pluginAllow = config?.plugins?.allow;
  results.push({
    id: 'plugin:allowlist',
    category: 'plugin',
    check: '插件白名单',
    status: pluginAllow && Array.isArray(pluginAllow) && pluginAllow.length > 0 ? 'pass' : 'fail',
    severity: 'high',
    message: pluginAllow && pluginAllow.length > 0 
      ? `已配置插件白名单: ${pluginAllow.length} 个` 
      : '未配置插件白名单，可能允许恶意插件加载\n     手动修复: openclaw config set --json plugins.allow \'["feishu","openclaw-tavily"]\'',
    // 需要手动执行 openclaw 命令
    fixCommand: undefined,
  });

  // 4.2 插件目录权限
  const extPerms = getFilePermissions(EXTENSIONS_DIR);
  results.push({
    id: 'plugin:permissions',
    category: 'plugin',
    check: '扩展目录权限',
    status: extPerms === '755' || extPerms === '700' ? 'pass' : 'warning',
    severity: 'medium',
    message: extPerms === '755' || extPerms === '700' 
      ? '扩展目录权限正确' 
      : `扩展目录权限: ${extPerms}`,
    fixCommand: extPerms !== '755' && extPerms !== '700' ? `chmod 755 "${EXTENSIONS_DIR}"` : undefined,
  });

  // 4.3 未知插件检测
  const loadedPlugins = config?.plugins?.entries ? Object.keys(config.plugins.entries) : [];
  const allowedPlugins = config?.plugins?.allow || [];
  const unknownPlugins = loadedPlugins.filter(p => !allowedPlugins.includes(p));
  
  results.push({
    id: 'plugin:unknown',
    category: 'plugin',
    check: '未授权插件',
    status: unknownPlugins.length === 0 ? 'pass' : 'warning',
    severity: 'medium',
    message: unknownPlugins.length === 0 
      ? '所有插件均在白名单中' 
      : `发现未授权插件: ${unknownPlugins.join(', ')}`,
  });

  return results;
}

// 5. 会话安全检测
async function checkSessionSecurity() {
  const results = [];
  const SESSIONS_PARENT_DIR = join(OPENCLAW_PATH, 'agents', 'main');

  // 5.1 会话目录权限
  const sessionsPerms = getFilePermissions(SESSIONS_DIR);
  const parentPerms = getFilePermissions(SESSIONS_PARENT_DIR);
  const sessionsStatus = (sessionsPerms === '700' || sessionsPerms === '600') ? 'pass' : 'fail';
  const parentStatus = (parentPerms === '700' || parentPerms === '600') ? 'pass' : 'fail';
  
  results.push({
    id: 'session:permissions',
    category: 'session',
    check: '会话目录权限',
    status: sessionsStatus === 'pass' && parentStatus === 'pass' ? 'pass' : 'fail',
    severity: 'high',
    message: sessionsStatus === 'pass' && parentStatus === 'pass'
      ? '会话目录权限正确' 
      : `会话目录权限过于宽松: sessions=${sessionsPerms}, parent=${parentPerms}`,
    current: `sessions=${sessionsPerms}, parent=${parentPerms}`,
    expected: '700 或 600',
    fixCommand: sessionsStatus !== 'pass' || parentStatus !== 'pass' 
      ? `chmod 700 "${SESSIONS_PARENT_DIR}" "${SESSIONS_DIR}"`
      : undefined,
  });

  // 5.2 会话文件权限
  try {
    if (existsSync(SESSIONS_DIR)) {
      const files = readdirSync(SESSIONS_DIR).filter(f => f.endsWith('.json'));
      const permIssues = files.filter(f => {
        const path = join(SESSIONS_DIR, f);
        return isFileReadableByOthers(path);
      });
      
      results.push({
        id: 'session:file-permissions',
        category: 'session',
        check: '会话文件权限',
        status: permIssues.length === 0 ? 'pass' : 'fail',
        severity: 'critical',
        message: permIssues.length === 0 
          ? '所有会话文件权限正确' 
          : `发现权限过宽的会话文件: ${permIssues.length} 个`,
        fixCommand: permIssues.length > 0 ? `find "${SESSIONS_DIR}" -name "*.json" -exec chmod 600 {} \\;` : undefined,
      });
    }
  } catch {
    // Sessions dir might not exist
  }

  // 5.3 孤立会话文件
  try {
    if (existsSync(SESSIONS_DIR)) {
      const orphaned = execSync(
        `ls -la "${SESSIONS_DIR}" 2>/dev/null | grep -E '\\.js$|\\.lock$' | wc -l`,
        { encoding: 'utf8' }
      ).trim();
      
      const orphanCount = parseInt(orphaned) || 0;
      results.push({
        id: 'session:orphaned',
        category: 'session',
        check: '孤立会话文件',
        status: orphanCount === 0 ? 'pass' : 'info',
        severity: 'low',
        message: orphanCount === 0 
          ? '未发现孤立会话文件' 
          : `发现 ${orphanCount} 个孤立文件（可清理）`,
        fixCommand: orphanCount > 0 ? `find "${SESSIONS_DIR}" -name "*.lock" -delete` : undefined,
      });
    }
  } catch {
    // Ignore
  }

  return results;
}

// 6. 文件系统安全检测
async function checkFilesystemSecurity() {
  const results = [];

  // 6.1 Workspace 权限
  const workspacePerms = getFilePermissions(WORKSPACE_DIR);
  results.push({
    id: 'filesystem:workspace',
    category: 'filesystem',
    check: 'Workspace 目录权限',
    status: workspacePerms === '755' || workspacePerms === '700' ? 'pass' : 'warning',
    severity: 'medium',
    message: workspacePerms === '755' || workspacePerms === '700' 
      ? 'Workspace 权限正确' 
      : `Workspace 权限: ${workspacePerms}`,
    current: workspacePerms,
    expected: '755 或 700',
  });

  // 6.2 敏感文件检测
  const sensitiveFiles = [
    '.env', '.env.local', '.env.production',
    'credentials.json', 'secrets.json',
    'id_rsa', 'id_ed25519',
    '.npmrc', '.pypirc',
  ];
  
  const foundSensitive = [];
  try {
    const files = readdirSync(WORKSPACE_DIR);
    for (const file of files) {
      if (sensitiveFiles.includes(file.toLowerCase())) {
        foundSensitive.push(file);
      }
    }
  } catch {
    // Ignore
  }

  results.push({
    id: 'filesystem:sensitive',
    category: 'filesystem',
    check: '敏感文件检测',
    status: foundSensitive.length === 0 ? 'pass' : 'warning',
    severity: 'high',
    message: foundSensitive.length === 0 
      ? '未发现敏感文件' 
      : `发现敏感文件: ${foundSensitive.join(', ')}`,
    fixCommand: foundSensitive.length > 0 ? '移动敏感文件到 ~/.secrets/ 或其他安全位置' : undefined,
  });

  // 6.3 OpenClaw 目录权限
  const openclawPerms = getFilePermissions(OPENCLAW_PATH);
  results.push({
    id: 'filesystem:root',
    category: 'filesystem',
    check: 'OpenClaw 根目录权限',
    status: openclawPerms === '755' ? 'pass' : 'warning',
    severity: 'medium',
    message: openclawPerms === '755' 
      ? 'OpenClaw 根目录权限正确' 
      : `权限: ${openclawPerms}`,
    current: openclawPerms,
    expected: '755',
  });

  return results;
}

// 7. 沙箱/扩展安全检测
async function checkSandboxSecurity() {
  const results = [];
  const config = loadConfig();

  // 7.1 exec 权限
  const execPolicy = config?.security?.execPolicy || config?.exec?.policy;
  results.push({
    id: 'sandbox:exec',
    category: 'sandbox',
    check: '命令执行策略',
    status: !execPolicy || execPolicy === 'deny' ? 'pass' : execPolicy === 'allowlist' ? 'pass' : 'warning',
    severity: execPolicy === 'allow' ? 'critical' : 'medium',
    message: !execPolicy 
      ? '未配置 exec 策略（默认 deny）' 
      : execPolicy === 'allow' 
        ? 'exec 设置为 allow，风险较高'
        : `exec 策略: ${execPolicy}`,
    fixCommand: execPolicy === 'allow' ? 'openclaw config set security.execPolicy "deny"' : undefined,
  });

  // 7.2 浏览器控制
  const browserEnabled = config?.browser?.enabled || config?.features?.browser;
  results.push({
    id: 'sandbox:browser',
    category: 'sandbox',
    check: '浏览器控制',
    status: !browserEnabled ? 'pass' : 'warning',
    severity: 'medium',
    message: browserEnabled 
      ? '已启用浏览器控制（确保信任使用的页面）' 
      : '未启用浏览器控制',
  });

  // 7.3 节点访问
  const nodeAccess = config?.nodes?.enabled || config?.features?.nodes;
  results.push({
    id: 'sandbox:nodes',
    category: 'sandbox',
    check: '设备节点访问',
    status: !nodeAccess ? 'pass' : 'warning',
    severity: 'medium',
    message: nodeAccess 
      ? '已启用设备节点访问（摄像头、屏幕等）' 
      : '未启用设备节点访问',
  });

  return results;
}

// 8. 云端部署检测
async function checkCloudSecurity() {
  const results = [];
  const deployment = detectDeploymentType();
  const config = loadConfig();

  if (deployment !== 'cloud') {
    results.push({
      id: 'cloud:deployment',
      category: 'cloud',
      check: '部署类型',
      status: 'skip',
      severity: 'info',
      message: '本地部署，跳过云端检测',
    });
    return results;
  }

  // 8.1 容器用户
  const runningAsRoot = process.getuid && process.getuid() === 0;
  results.push({
    id: 'cloud:container-user',
    category: 'cloud',
    check: '容器运行用户',
    status: !runningAsRoot ? 'pass' : 'fail',
    severity: 'critical',
    message: runningAsRoot 
      ? '以 root 用户运行容器，风险较高' 
      : '以非 root 用户运行',
    fixCommand: runningAsRoot ? '使用非 root 用户运行容器' : undefined,
  });

  // 8.2 环境变量 secrets
  const sensitiveEnvVars = process.env;
  const hasSensitive = Object.keys(sensitiveEnvVars).some(k => 
    k.includes('SECRET') || k.includes('KEY') || k.includes('TOKEN') || k.includes('PASSWORD')
  );
  
  results.push({
    id: 'cloud:env-secrets',
    category: 'cloud',
    check: '环境变量敏感信息',
    status: !hasSensitive ? 'pass' : 'warning',
    severity: 'high',
    message: hasSensitive 
      ? '环境变量中可能包含敏感信息，建议使用 secrets 管理' 
      : '未在环境变量中发现明显敏感信息',
  });

  // 8.3 日志级别
  const logLevel = config?.logLevel || config?.logging?.level;
  results.push({
    id: 'cloud:log-level',
    category: 'cloud',
    check: '日志级别',
    status: logLevel === 'error' || logLevel === 'warn' ? 'pass' : 'warning',
    severity: 'low',
    message: logLevel === 'error' || logLevel === 'warn' 
      ? '日志级别适当' 
      : `日志级别: ${logLevel || 'default'}（建议生产环境用 error/warn）`,
  });

  return results;
}

// ============================================================================
// 9. 后门/木马检测
// ============================================================================

const SUSPICIOUS_PATTERNS = [
  { pattern: /\.bak$/, desc: '备份文件', severity: 'low' },
  { pattern: /\.tmp$/, desc: '临时文件', severity: 'low' },
  { pattern: /\.sh$/, desc: 'Shell脚本', severity: 'medium' },
  { pattern: /\.py$/, desc: 'Python脚本', severity: 'medium' },
  { pattern: /\.exe$/, desc: '可执行文件', severity: 'critical' },
  { pattern: /\.dll$/, desc: '动态库', severity: 'critical' },
];

const SUSPICIOUS_CMD_PATTERNS = [
  { pattern: /wget|curl.+\|sh/, desc: '远程脚本执行', severity: 'critical' },
  { pattern: /nc\s+-|netcat|ncat/, desc: '网络工具', severity: 'high' },
  { pattern: /powershell.*-enc/i, desc: '编码命令', severity: 'critical' },
  { pattern: /base64.*-d/i, desc: 'Base64解码', severity: 'high' },
  { pattern: /eval\s*\(|exec\s*\(|system\s*\(/, desc: '命令执行', severity: 'high' },
  { pattern: /shell_exec|passthru|popen/, desc: '执行函数', severity: 'high' },
  { pattern: /\/etc\/passwd|\/etc\/shadow/, desc: '系统文件', severity: 'high' },
  { pattern: /union.*select/i, desc: 'SQL注入', severity: 'critical' },
  { pattern: /<\?php|<\?\s*script/i, desc: '恶意代码', severity: 'critical' },
];

async function checkMalware() {
  const results = [];
  
  // 9.1 扫描可疑文件
  const susFiles = [];
  function scanDir(dir, depth = 0) {
    if (depth > 4) return;
    try {
      if (!existsSync(dir)) return;
      const files = readdirSync(dir);
      for (const file of files) {
        const fullPath = join(dir, file);
        try {
          const stat = statSync(fullPath);
          if (stat.isDirectory()) {
            if (file === 'node_modules' || file === '.git') continue;
            scanDir(fullPath, depth + 1);
          } else if (stat.isFile()) {
            for (const sus of SUSPICIOUS_PATTERNS) {
              if (sus.pattern.test(file)) {
                susFiles.push({ path: fullPath, reason: sus.desc, severity: sus.severity });
                break;
              }
            }
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  }
  scanDir(OPENCLAW_PATH);
  
  results.push({
    id: 'malware:suspicious-files',
    category: 'malware',
    check: '可疑文件检测',
    status: susFiles.length === 0 ? 'pass' : 'warning',
    severity: susFiles.length === 0 ? 'low' : 'medium',
    message: susFiles.length === 0 ? '未发现可疑文件' : `发现 ${susFiles.length} 个可疑文件`,
    current: susFiles.length > 0 ? susFiles.slice(0, 5).map(f => f.path.split('/').pop()).join(', ') : undefined,
  });
  
  // 9.2 检查可疑代码
  const susCode = [];
  function scanCode(dir, depth = 0) {
    if (depth > 3) return;
    try {
      if (!existsSync(dir)) return;
      const files = readdirSync(dir);
      for (const file of files) {
        const fullPath = join(dir, file);
        try {
          const stat = statSync(fullPath);
          if (stat.isDirectory()) {
            if (file === 'node_modules' || file === '.git' || file === '__pycache__') continue;
            scanCode(fullPath, depth + 1);
          } else if (stat.isFile() && /\.(js|ts|py|sh|rb|go|ps1)$/.test(file)) {
            if (stat.size > 512 * 1024) return;
            const content = readFileSync(fullPath, 'utf8');
            for (const sus of SUSPICIOUS_CMD_PATTERNS) {
              if (sus.pattern.test(content)) {
                susCode.push({ path: fullPath, reason: sus.desc, severity: sus.severity });
                break;
              }
            }
          }
        } catch { /* skip */ }
      }
    } catch { /* skip */ }
  }
  scanCode(OPENCLAW_PATH);
  
  results.push({
    id: 'malware:suspicious-code',
    category: 'malware',
    check: '可疑代码检测',
    status: susCode.length === 0 ? 'pass' : susCode.length < 3 ? 'warning' : 'fail',
    severity: susCode.length === 0 ? 'low' : susCode.length < 3 ? 'medium' : 'high',
    message: susCode.length === 0 ? '未发现可疑代码' : `发现 ${susCode.length} 处可疑代码`,
    current: susCode.length > 0 ? susCode.slice(0, 3).map(c => c.reason).join(', ') : undefined,
  });
  
  results.push({
    id: 'malware:network',
    category: 'malware',
    check: '异常网络连接',
    status: 'info',
    severity: 'low',
    message: '需手动检查: lsof -i | grep -v LISTEN',
  });
  
  return results;
}

// ============================================================================
// 10. 安全漏洞检测
// ============================================================================

const KNOWN_VULN_PKGS = {
  'axios': '<1.6.0', 'lodash': '<4.17.21', 'moment': '<2.29.4',
  'minimist': '<1.2.8', 'json5': '<1.0.2', 'ws': '<8.0.0',
};

async function checkVulnerability() {
  const results = [];
  const config = loadConfig();
  
  // 10.1 OpenClaw 版本
  let version = 'unknown';
  try {
    const pkgPath = join(OPENCLAW_PATH, 'package.json');
    if (existsSync(pkgPath)) {
      version = JSON.parse(readFileSync(pkgPath, 'utf8')).version || 'unknown';
    }
  } catch { /* ignore */ }
  
  results.push({
    id: 'vuln:version',
    category: 'vulnerability',
    check: 'OpenClaw 版本',
    status: version !== 'unknown' ? 'pass' : 'warning',
    severity: 'low',
    message: `当前版本: ${version}`,
    current: version,
  });
  
  // 10.2 Node 版本
  const nodeVer = process.version;
  const nodeMajor = parseInt(nodeVer.replace('v', '').split('.')[0]);
  results.push({
    id: 'vuln:node-version',
    category: 'vulnerability',
    check: 'Node.js 版本',
    status: nodeMajor >= 18 ? 'pass' : 'warning',
    severity: nodeMajor >= 18 ? 'low' : 'medium',
    message: nodeMajor >= 18 ? `Node.js 版本正常: ${nodeVer}` : `Node.js 版本过低: ${nodeVer}`,
    current: nodeVer,
    fixCommand: nodeMajor < 18 ? '升级 Node.js 到 18+' : undefined,
  });
  
  // 10.3 依赖包漏洞
  const vulnDeps = [];
  try {
    const nodeModules = join(OPENCLAW_PATH, 'node_modules');
    if (existsSync(nodeModules)) {
      const pkgs = readdirSync(nodeModules);
      for (const pkg of pkgs) {
        if (KNOWN_VULN_PKGS[pkg]) {
          const pkgJsonPath = join(nodeModules, pkg, 'package.json');
          if (existsSync(pkgJsonPath)) {
            const pkgVer = JSON.parse(readFileSync(pkgJsonPath, 'utf8')).version || '0';
            const minVer = KNOWN_VULN_PKGS[pkg].replace('<', '');
            if (pkgVer.localeCompare(minVer, undefined, { numeric: true }) < 0) {
              vulnDeps.push(pkg + '@' + pkgVer);
            }
          }
        }
      }
    }
  } catch { /* ignore */ }
  
  results.push({
    id: 'vuln:dependencies',
    category: 'vulnerability',
    check: '依赖包漏洞',
    status: vulnDeps.length === 0 ? 'pass' : 'fail',
    severity: vulnDeps.length === 0 ? 'low' : 'high',
    message: vulnDeps.length === 0 ? '依赖包无已知漏洞' : '存在漏洞: ' + vulnDeps.join(', '),
    current: vulnDeps.length > 0 ? vulnDeps.join(', ') : undefined,
    fixCommand: vulnDeps.length > 0 ? 'npm audit fix' : undefined,
  });
  
  // 10.4 配置漏洞
  const configVulns = [];
  if (config) {
    if (config.debug === true) configVulns.push('debug模式开启');
    if (config.logLevel === 'debug') configVulns.push('日志级别debug');
    if (config.cors && config.cors.origin === '*') configVulns.push('CORS允许所有');
    if (config.security && config.security.execPolicy === 'allow') configVulns.push('exec策略过松');
  }
  
  results.push({
    id: 'vuln:config',
    category: 'vulnerability',
    check: '配置安全漏洞',
    status: configVulns.length === 0 ? 'pass' : 'fail',
    severity: configVulns.length === 0 ? 'low' : 'high',
    message: configVulns.length === 0 ? '配置无明显漏洞' : '发现: ' + configVulns.join(', '),
    current: configVulns.length > 0 ? configVulns.join(', ') : undefined,
  });
  
  return results;
}


// ============================================================================
// 修复模块
// ============================================================================

async function applyFix(result) {
  if (!result.fixCommand) {
    console.log(`  ⏭️  ${result.check}: 无自动修复命令`);
    return false;
  }

  try {
    console.log(`  🔧 执行: ${result.fixCommand}`);
    execSync(result.fixCommand, { encoding: 'utf8', stdio: 'pipe' });
    console.log(`  ✅ 修复成功`);
    return true;
  } catch (err) {
    console.log(`  ❌ 修复失败: ${err.message}`);
    return false;
  }
}

// ============================================================================
// 主程序
// ============================================================================

async function main() {
  const showHelp = args.help;
  const doFix = args.fix;
  const outputJson = args.json;
  const listChecks = args.list;
  const categoryArg = args.category;
  const verbose = args.verbose;

  if (showHelp) {
    console.log(`
🛡️  OpenClaw Security Scanner v1.0.0

用法:
  security-scan                    检测所有安全问题
  security-scan --fix              检测并自动修复
  security-scan --json             JSON 格式输出
  security-scan --path=/custom     指定 OpenClaw 目录
  security-scan --category=config  只检测指定类别
  security-scan --list            列出所有检测项
  security-scan --verbose          详细输出

类别:
  config     配置安全
  network    网络安全
  auth       认证安全
  plugin     插件安全
  session    会话安全
  filesystem 文件系统
  sandbox    沙箱安全
  cloud      云端部署

示例:
  security-scan --category=network
  security-scan --fix --category=config
`);
    process.exit(0);
  }

  if (listChecks) {
    console.log('可用的检测项:\n');
    for (const [key, desc] of Object.entries(CATEGORIES)) {
      console.log(`  ${key.padEnd(12)} ${desc}`);
    }
    process.exit(0);
  }

  console.log('🛡️  OpenClaw Security Scanner\n');
  const displayPath = args.path ? `${OPENCLAW_PATH} (自定义)` : `${OPENCLAW_PATH}`;
  console.log(`📍 OpenClaw 目录: ${displayPath}`);
  console.log(`🖥️  部署类型: ${detectDeploymentType()}`);
  console.log(`📦 版本: ${getOpenClawVersion()}\n`);

  // 运行检测
  const checkModules = {
    config: checkConfigSecurity,
    network: checkNetworkSecurity,
    auth: checkAuthSecurity,
    plugin: checkPluginSecurity,
    session: checkSessionSecurity,
    filesystem: checkFilesystemSecurity,
    sandbox: checkSandboxSecurity,
    cloud: checkCloudSecurity,
    malware: checkMalware,
    vulnerability: checkVulnerability,
  };

  const categories = categoryArg ? [categoryArg] : Object.keys(CATEGORIES);
  const allResults = [];

  for (const cat of categories) {
    if (checkModules[cat]) {
      if (verbose) console.log(`\n📂 检测: ${CATEGORIES[cat]}`);
      const results = await checkModules[cat]();
      allResults.push(...results);
    }
  }

  // 统计
  const summary = {
    total: allResults.length,
    passed: allResults.filter(r => r.status === 'pass').length,
    failed: allResults.filter(r => r.status === 'fail').length,
    warnings: allResults.filter(r => r.status === 'warning').length,
    skipped: allResults.filter(r => r.status === 'skip').length,
  };

  // 计算风险分数
  const severityScores = allResults
    .filter(r => r.status !== 'pass' && r.status !== 'skip')
    .map(r => SEVERITY_ORDER[r.severity] ?? 4);
  const avgScore = severityScores.length > 0 
    ? severityScores.reduce((a, b) => a + b, 0) / severityScores.length 
    : 0;
  const riskScore = Math.round((1 - avgScore / 4) * 100);

  // 生成报告
  const report = {
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: {
      os: process.platform,
      deployment: detectDeploymentType(),
      openclawPath: OPENCLAW_PATH,
      configExists: existsSync(CONFIG_FILE),
    },
    summary: { ...summary, riskScore },
    results: allResults,
    recommendations: allResults
      .filter(r => r.status !== 'pass' && r.fix)
      .map(r => `[${r.severity.toUpperCase()}] ${r.check}: ${r.message}`),
  };

  if (outputJson) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(0);
  }

  // 控制台输出
  console.log('─'.repeat(50));
  console.log(`\n📊 检测结果:`);
  console.log(`   ✅ 通过: ${summary.passed}`);
  console.log(`   ❌ 失败: ${summary.failed}`);
  console.log(`   ⚠️  警告: ${summary.warnings}`);
  console.log(`   ⏭️  跳过: ${summary.skipped}`);
  console.log(`   🎯 风险分数: ${riskScore}/100`);

  // 显示失败项
  const failedResults = allResults.filter(r => r.status === 'fail');
  if (failedResults.length > 0) {
    console.log(`\n❌ 需要修复的问题 (${failedResults.length}):\n`);
    for (const r of failedResults) {
      const severityEmoji = r.severity === 'critical' ? '🔴' : r.severity === 'high' ? '🟠' : '🟡';
      console.log(`  ${severityEmoji} [${r.severity}] ${r.check}`);
      console.log(`     ${r.message}`);
      if (r.fixCommand) {
        console.log(`     修复: ${r.fixCommand}`);
      }
      console.log('');
    }
  }

  // 显示警告项
  const warningResults = allResults.filter(r => r.status === 'warning');
  if (warningResults.length > 0 && verbose) {
    console.log(`\n⚠️  警告项 (${warningResults.length}):\n`);
    for (const r of warningResults) {
      console.log(`  • ${r.check}: ${r.message}`);
    }
  }

  // 自动修复
  if (doFix && failedResults.length > 0) {
    console.log('\n' + '─'.repeat(50));
    console.log('\n🔧 开始自动修复...\n');

    let fixedCount = 0;
    for (const r of failedResults) {
      const success = await applyFix(r);
      if (success) fixedCount++;
    }

    console.log(`\n✅ 修复完成: ${fixedCount}/${failedResults.length}`);

    // 重新检测
    console.log('\n📋 重新检测...\n');
    const newResults = [];
    for (const cat of categories) {
      if (checkModules[cat]) {
        const results = await checkModules[cat]();
        newResults.push(...results);
      }
    }

    const newFailed = newResults.filter(r => r.status === 'fail').length;
    const newPassed = newResults.filter(r => r.status === 'pass').length;

    console.log(`   修复后: ✅ ${newPassed} | ❌ ${newFailed}`);
    
    if (newFailed === 0) {
      console.log('\n🎉 所有问题已修复！');
    } else {
      console.log(`\n⚠️  还有 ${newFailed} 个问题需要手动处理`);
    }
  } else if (failedResults.length > 0) {
    console.log('\n💡 运行 `security-scan --fix` 自动修复问题');
  }

  // 建议
  if (report.recommendations.length > 0) {
    console.log('\n📝 建议:');
    for (const rec of report.recommendations.slice(0, 5)) {
      console.log(`   • ${rec}`);
    }
  }

  console.log('');
}

// 运行
main().catch(console.error);
