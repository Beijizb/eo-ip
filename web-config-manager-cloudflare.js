// EdgeOne 优选IP Web配置管理器 - Cloudflare Worker专用版本
// 完全兼容Cloudflare Worker环境，使用Web标准API

// Polyfill for crypto.randomUUID (浏览器兼容性修复)
if (!crypto.randomUUID) {
  crypto.randomUUID = function() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  };
}

// 默认配置
const DEFAULT_CONFIG = {
  DOMAINS: [
    {
      name: 'example.com',
      type: 'A',
      proxied: true,
      ttl: 1
    }
  ],
  WEICE_URL: 'https://www.weicede.com/index/api/node_list.html',
  MAX_IPS: 5,
  TIMEOUT: 2000,
  UPDATE_INTERVAL: '0 */6 * * *',
  FILTER_OPTIONS: {
    MAX_LATENCY: 500, // ms
    MIN_SPEED: 500,   // kB/s
    MIN_BANDWIDTH: 5, // MB
  },
  ENABLE_LOGS: false,
  LOG_LEVEL: 'info',
  ENABLE_NOTIFICATION: false,
  BOT_TOKEN: '',
  CHAT_ID: '',
  NOTIFY_SUCCESS: true,
  NOTIFY_ERROR: true,
  ENABLE_AUTH: true,
  ADMIN_PASSWORD: '' // 密码必须通过环境变量设置
};

// 存储键名
const LOGS_STORAGE_KEY = 'worker_logs';
const AUTH_SESSIONS_KEY = 'auth_sessions';

// 环境变量验证
function validateEnvironment() {
  const required = ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ZONE_ID'];
  const missing = [];
  
  for (const key of required) {
    if (!globalThis[key]) {
      missing.push(key);
    }
  }
  
  return {
    valid: missing.length === 0,
    missing
  };
}

async function healthCheck() {
  const checks = {
    environment: validateEnvironment(),
    kv_storage: typeof WORKER_CONFIG !== 'undefined',
    timestamp: new Date().toISOString()
  };
  
  const allHealthy = checks.environment.valid && checks.kv_storage;
  
  return {
    status: allHealthy ? 'healthy' : 'degraded',
    checks,
    uptime: Date.now()
  };
}

// 限流机制
const rateLimitMap = new Map();

function checkRateLimit(clientIP, maxRequests = 60, windowMs = 60000) {
  const now = Date.now();
  const windowStart = now - windowMs;
  
  if (!rateLimitMap.has(clientIP)) {
    rateLimitMap.set(clientIP, []);
  }
  
  const requests = rateLimitMap.get(clientIP);
  
  // 清理过期请求
  const validRequests = requests.filter(time => time > windowStart);
  
  if (validRequests.length >= maxRequests) {
    const error = new Error('请求过于频繁，请稍后再试');
    error.statusCode = 429;
    throw error;
  }
  
  validRequests.push(now);
  rateLimitMap.set(clientIP, validRequests);
}

// 生成请求ID
function generateRequestId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 9);
}

// JWT实现 - 使用Web Crypto API

// 在顶层作用域定义一个变量来缓存密钥，以减少对KV的频繁读取
let jwtSecretCache;

async function getSecretKey() {
  // 优先使用内存缓存
  if (jwtSecretCache) {
    return jwtSecretCache;
  }

  const KV_SECRET_KEY = 'jwt_secret';

  // 尝试从KV存储中获取密钥
  let secret = await WORKER_CONFIG.get(KV_SECRET_KEY);

  if (secret) {
    jwtSecretCache = secret; // 缓存到内存
    return secret;
  }

  // 如果KV中没有密钥，则生成一个新的、高强度的密钥
  // 使用Web Crypto API生成安全的随机字节
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  secret = Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');

  // 将新密钥存入KV，并设置一个较长的过期时间（例如一年），或不设置使其永久有效
  // 同时将其存入内存缓存
  await WORKER_CONFIG.put(KV_SECRET_KEY, secret);
  jwtSecretCache = secret;
  
  console.log('已生成并持久化新的JWT密钥。');

  return secret;
}

// Base64URL编码/解码
function base64UrlEncode(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  const decoded = atob(str);
  return new TextDecoder().decode(new Uint8Array([...decoded].map(c => c.charCodeAt(0))));
}

// HMAC-SHA256签名
async function hmacSha256(key, data) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(key);
  const messageData = encoder.encode(data);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  const signatureArray = new Uint8Array(signature);
  
  return btoa(String.fromCharCode(...signatureArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

async function generateToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  
  const secretKey = await getSecretKey();
  const signature = await hmacSha256(secretKey, encodedHeader + '.' + encodedPayload);
    
  return encodedHeader + '.' + encodedPayload + '.' + signature;
}

async function verifyToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const [encodedHeader, encodedPayload, signature] = parts;
    
    const secretKey = await getSecretKey();
    const expectedSignature = await hmacSha256(secretKey, encodedHeader + '.' + encodedPayload);
    
    if (signature !== expectedSignature) {
      console.warn('JWT签名验证失败');
      return null;
    }
    
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    
    if (payload.exp && Date.now() > payload.exp) {
      console.warn('JWT已过期');
      return null;
    }
    
    return payload;
  } catch (error) {
    console.error('JWT验证错误:', error.message);
    return null;
  }
}

// 认证函数
async function authenticateUser(password) {
  const config = await getConfig();

  if (!config.ENABLE_AUTH) {
    return { success: true, token: null };
  }

  // 强制要求通过环境变量设置密码
  if (!config.ADMIN_PASSWORD) {
    await logMessage('error', '认证失败：未设置ADMIN_PASSWORD环境变量');
    return { success: false, error: '系统未配置认证密码，请联系管理员' };
  }

  if (password === config.ADMIN_PASSWORD) {
    const payload = {
      authenticated: true,
      exp: Date.now() + 24 * 60 * 60 * 1000, // 24小时有效期
    };
    const token = await generateToken(payload);

    await logMessage('info', '用户登录成功');
    return { success: true, token };
  }

  await logMessage('warn', '用户登录失败：密码错误');
  return { success: false, error: '密码错误' };
}

async function verifyAuth(request) {
  const config = await getConfig();
  
  if (!config.ENABLE_AUTH) {
    return true;
  }
  
  const authHeader = request.headers.get('Authorization');
  const cookieHeader = request.headers.get('Cookie');
  
  let token = null;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  }
  
  if (!token && cookieHeader) {
    const cookies = cookieHeader.split(';').reduce((acc, cookie) => {
      const [key, value] = cookie.trim().split('=');
      acc[key] = value;
      return acc;
    }, {});
    token = cookies.auth_token;
  }
  
  if (!token) {
    return false;
  }
  
  const payload = await verifyToken(token);
  return payload && payload.authenticated;
}

// 配置管理
// 优先从KV存储中读取，如果KV中没有，则回退到环境变量
async function getConfig() {
  // 尝试从KV获取配置
  const kvConfigStr = typeof WORKER_CONFIG !== 'undefined' ? await WORKER_CONFIG.get('worker_config') : null;
  let kvConfig = {};
  if (kvConfigStr) {
    try {
      kvConfig = JSON.parse(kvConfigStr);
    } catch (e) {
      console.error('无法解析存储在KV中的配置:', e);
    }
  }

  // 从环境变量获取基础和敏感配置
  const envConfig = { ...DEFAULT_CONFIG };
  const envMappings = {
    DOMAINS: (val) => {
      try {
        return typeof val === 'string' ? JSON.parse(val) : val;
      } catch (e) {
        console.error('域名配置解析失败:', e);
        return envConfig.DOMAINS; // fallback to default
      }
    },
    WEICE_URL: 'WEICE_URL',
    MAX_IPS: (val) => parseInt(val, 10) || envConfig.MAX_IPS,
    TIMEOUT: (val) => parseInt(val, 10) || envConfig.TIMEOUT,
    UPDATE_INTERVAL: 'UPDATE_INTERVAL',
    ENABLE_LOGS: (val) => val === 'true',
    LOG_LEVEL: 'LOG_LEVEL',
    ENABLE_NOTIFICATION: (val) => val === 'true',
    BOT_TOKEN: 'BOT_TOKEN',
    CHAT_ID: 'CHAT_ID',
    NOTIFY_SUCCESS: (val) => val === 'true',
    NOTIFY_ERROR: (val) => val === 'true',
    ENABLE_AUTH: (val) => val === 'true',
    ADMIN_PASSWORD: 'ADMIN_PASSWORD',
    JWT_SECRET: 'JWT_SECRET'
  };

  for (const [key, mapper] of Object.entries(envMappings)) {
    if (globalThis[key] !== undefined) {
      envConfig[key] = typeof mapper === 'function' ? mapper(globalThis[key]) : globalThis[key];
    }
  }

  // 合并配置，KV中的配置优先级更高，但敏感信息始终来自环境变量
  const finalConfig = {
    ...envConfig,
    ...kvConfig, // KV中的非敏感配置会覆盖环境变量中的
    // 确保敏感信息始终来自环境变量，不可被页面修改
    ADMIN_PASSWORD: envConfig.ADMIN_PASSWORD,
    JWT_SECRET: envConfig.JWT_SECRET,
    CLOUDFLARE_API_TOKEN: envConfig.CLOUDFLARE_API_TOKEN,
    BOT_TOKEN: envConfig.BOT_TOKEN,
    CHAT_ID: envConfig.CHAT_ID,
  };

  return finalConfig;
}

// 日志记录
async function logMessage(level, message, data = {}, requestId = null) {
  const config = await getConfig();
  
  if (!config.ENABLE_LOGS) return;
  
  const logEntry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    data,
    requestId
  };
  
  // 始终在控制台输出日志
  console.log(`[${level.toUpperCase()}] ${message}`, JSON.stringify(data));
  
  // 优化KV写入：仅在必要时写入，并使用更高效的方式
  try {
    if (typeof WORKER_CONFIG !== 'undefined' && (level === 'error' || level === 'warn')) {
      // 为避免性能问题，可以考虑将日志推送到专门的日志服务，
      // 或者使用更高效的存储策略，例如按天或按小时分片存储。
      // 此处简化为仅记录错误和警告到KV，并追加而不是读写整个数组。
      const logKey = `log:${new Date().toISOString()}`;
      await WORKER_CONFIG.put(logKey, JSON.stringify(logEntry), { expirationTtl: 86400 * 7 }); // 保存7天
    }
  } catch (error) {
    console.error('保存日志到KV失败:', error);
  }
}

// 性能监控
async function logPerformance(operation, duration, success, metadata = {}) {
  await logMessage('info', 'performance_metric', {
    operation,
    duration_ms: duration,
    success,
    ...metadata
  });
}

// 安全事件记录
async function logSecurityEvent(event, clientIP, metadata = {}) {
  await logMessage('warn', 'security_event', {
    event,
    client_ip: clientIP,
    timestamp: Date.now(),
    ...metadata
  });
}

// 登录页面生成
function generateLoginPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 EdgeOne 优选IP - 登录验证</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
        }
        .login-header h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 10px;
        }
        .login-header p {
            color: #666;
            font-size: 16px;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }
        .form-group input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        .login-btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease;
        }
        .login-btn:hover {
            transform: translateY(-2px);
        }
        .login-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        .alert {
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: none;
        }
        .alert.error {
            background-color: #fee;
            color: #c33;
            border: 1px solid #fcc;
        }
        .alert.success {
            background-color: #efe;
            color: #363;
            border: 1px solid #cfc;
        }
        .loading {
            display: none;
            margin-top: 10px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🔐 登录验证</h1>
            <p>请输入密码以访问配置管理界面</p>
        </div>
        
        <div id="alert" class="alert"></div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="password">🔒 密码</label>
                <input type="password" id="password" name="password" required placeholder="请输入登录密码">
            </div>
            
            <button type="submit" class="login-btn" id="loginBtn">
                🚀 登录
            </button>
            
            <div class="loading" id="loading">
                ⏳ 验证中...
            </div>
        </form>
    </div>
    
    <script>
        const loginForm = document.getElementById('loginForm');
        const loginBtn = document.getElementById('loginBtn');
        const loading = document.getElementById('loading');
        const alert = document.getElementById('alert');
        
        function showAlert(message, type = 'error') {
            alert.textContent = message;
            alert.className = \`alert \${type}\`;
            alert.style.display = 'block';
            
            setTimeout(() => {
                alert.style.display = 'none';
            }, 5000);
        }
        
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const password = document.getElementById('password').value;
            
            if (!password) {
                showAlert('请输入密码');
                return;
            }
            
            loginBtn.disabled = true;
            loading.style.display = 'block';
            
            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ password })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    showAlert('登录成功，正在跳转...', 'success');
                    
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1000);
                } else {
                    showAlert(result.error || '登录失败');
                }
            } catch (error) {
                console.error('登录错误:', error);
                showAlert('网络错误，请重试');
            } finally {
                loginBtn.disabled = false;
                loading.style.display = 'none';
            }
        });
        
        document.getElementById('password').focus();
    </script>
</body>
</html>`;
}

// 主请求处理函数
async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const requestId = generateRequestId();
  const startTime = Date.now();

  try {
    // 限流检查
    if (path.startsWith('/api/')) {
      try {
        checkRateLimit(clientIP, 60, 60000);
      } catch (error) {
        await logSecurityEvent('rate_limit_exceeded', clientIP, { path, method });
        return new Response(JSON.stringify({
          success: false,
          error: error.message
        }), {
          status: error.statusCode,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
    
    await logMessage('debug', 'request_start', {
      method, path, client_ip: clientIP
    }, requestId);
    
    // 健康检查
    if (path === '/health' && method === 'GET') {
      const health = await healthCheck();
      return new Response(JSON.stringify(health, null, 2), {
        status: health.status === 'healthy' ? 200 : 503,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Favicon处理
    if (path === '/favicon.ico' && method === 'GET') {
      // 返回SVG favicon
      const svgContent = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="32" height="32">
        <defs>
          <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#667eea;stop-opacity:1" />
            <stop offset="100%" style="stop-color:#764ba2;stop-opacity:1" />
          </linearGradient>
        </defs>
        <rect width="32" height="32" rx="6" fill="url(#grad)"/>
        <text x="16" y="22" font-family="Arial, sans-serif" font-size="18" font-weight="bold" text-anchor="middle" fill="white">E</text>
      </svg>`;
      
      return new Response(svgContent, {
        headers: { 
          'Content-Type': 'image/svg+xml',
          'Cache-Control': 'public, max-age=86400'
        }
      });
    }
    
    // 登录页面
    if (path === '/login' && method === 'GET') {
      return new Response(generateLoginPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }
    
    // 登录API
    if (path === '/api/auth/login' && method === 'POST') {
      try {
        const bodyText = await request.text();
        if (!bodyText) {
          throw new Error('请求体为空');
        }
        
        const body = JSON.parse(bodyText);
        const { password } = body;
        
        if (!password) {
          return new Response(JSON.stringify({
            success: false,
            error: '请输入密码'
          }), {
            status: 400,
            headers: { 'Content-Type': 'application/json' }
          });
        }
        
        const authResult = await authenticateUser(password);
        
        if (authResult.success) {
          const response = new Response(JSON.stringify({
            success: true,
            token: authResult.token,
            message: '登录成功'
          }), {
            headers: { 'Content-Type': 'application/json' }
          });
          
          if (authResult.token) {
            response.headers.set('Set-Cookie', 
              `auth_token=${authResult.token}; Path=/; Max-Age=86400; HttpOnly; SameSite=Strict`);
          }
          
          return response;
        } else {
          return new Response(JSON.stringify({
            success: false,
            error: authResult.error
          }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      } catch (error) {
        await logMessage('error', 'login_parse_error', {
          error: error.message,
          client_ip: clientIP
        }, requestId);
        
        return new Response(JSON.stringify({
          success: false,
          error: '请求格式错误: ' + error.message
        }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    }
    
    // 注销API
    if (path === '/api/auth/logout' && method === 'POST') {
      const response = new Response(JSON.stringify({
        success: true,
        message: '注销成功'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
      
      response.headers.set('Set-Cookie', 
        'auth_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict');
      
      return response;
    }
    
        // API: 获取配置
    if (path === '/api/config' && method === 'GET') {
      const isAuthenticated = await verifyAuth(request);
      if (!isAuthenticated) {
        return new Response(JSON.stringify({ success: false, error: '未授权' }), {
          status: 401, headers: { 'Content-Type': 'application/json' }
        });
      }
      const config = await getConfig();
      // 出于安全考虑，不返回敏感信息
      const { ADMIN_PASSWORD, JWT_SECRET, CLOUDFLARE_API_TOKEN, BOT_TOKEN, ...safeConfig } = config;
      return new Response(JSON.stringify({ success: true, config: safeConfig }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // API: 更新配置
    if (path === '/api/config' && method === 'POST') {
      const isAuthenticated = await verifyAuth(request);
      if (!isAuthenticated) {
        return new Response(JSON.stringify({ success: false, error: '未授权' }), {
          status: 401, headers: { 'Content-Type': 'application/json' }
        });
      }
      try {
        const newConfig = await request.json();

        // 获取KV中已有的配置
        const kvConfigStr = await WORKER_CONFIG.get('worker_config');
        const currentKvConfig = kvConfigStr ? JSON.parse(kvConfigStr) : {};

        // 将从表单提交的新配置合并到现有KV配置之上
        const updatedKvConfig = { ...currentKvConfig, ...newConfig };

        // 将合并后的配置写回KV
        await WORKER_CONFIG.put('worker_config', JSON.stringify(updatedKvConfig));
        await logMessage('info', '配置已更新', { user: 'admin' });
        return new Response(JSON.stringify({ success: true, message: '配置更新成功' }), {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (error) {
        await logMessage('error', '配置更新失败', { error: error.message });
        return new Response(JSON.stringify({ success: false, error: '更新失败：' + error.message }), {
          status: 400, headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // API: 手动筛选IP
    if (path === '/api/filter-ips' && method === 'POST') {
      const isAuthenticated = await verifyAuth(request);
      if (!isAuthenticated) {
        return new Response(JSON.stringify({ success: false, error: '未授权' }), {
          status: 401, headers: { 'Content-Type': 'application/json' }
        });
      }
      try {
        const { ips } = await request.json();
        
        if (!Array.isArray(ips) || ips.length === 0) {
          return new Response(JSON.stringify({ success: false, error: 'IP列表不能为空' }), {
            status: 400, headers: { 'Content-Type': 'application/json' }
          });
        }

        await logMessage('info', '开始手动IP筛选', { ip_count: ips.length, user: 'admin' });
        
        const config = await getConfig();
        const validIps = [];
        const results = [];
        
        // 并发测试IP，但限制并发数量避免过载
        const batchSize = 10;
        for (let i = 0; i < ips.length; i += batchSize) {
          const batch = ips.slice(i, i + batchSize);
          const batchPromises = batch.map(async (ip) => {
            try {
              // 简单的IP格式验证
              if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
                return { ip, valid: false, reason: '格式无效' };
              }
              
              // 基本连通性测试（这里可以根据需要添加更复杂的测试逻辑）
              const testUrl = `http://${ip}`;
              const controller = new AbortController();
              const timeoutId = setTimeout(() => controller.abort(), config.TIMEOUT || 5000);
              
              try {
                const response = await fetch(testUrl, {
                  method: 'HEAD',
                  signal: controller.signal,
                  headers: { 'User-Agent': 'EdgeOne-IP-Filter/1.0' }
                });
                clearTimeout(timeoutId);
                return { ip, valid: true, status: response.status };
              } catch (error) {
                clearTimeout(timeoutId);
                return { ip, valid: false, reason: error.message };
              }
            } catch (error) {
              return { ip, valid: false, reason: error.message };
            }
          });
          
          const batchResults = await Promise.all(batchPromises);
          results.push(...batchResults);
          
          // 收集有效IP
          batchResults.forEach(result => {
            if (result.valid) {
              validIps.push(result.ip);
            }
          });
        }
        
        // 将有效IP添加到现有配置中（这里可以根据实际需求调整存储逻辑）
        const kvConfigStr = await WORKER_CONFIG.get('worker_config');
        const currentKvConfig = kvConfigStr ? JSON.parse(kvConfigStr) : {};
        
        // 如果没有手动IP列表，创建一个
        if (!currentKvConfig.MANUAL_IPS) {
          currentKvConfig.MANUAL_IPS = [];
        }
        
        // 添加新的有效IP，避免重复
        const existingIps = new Set(currentKvConfig.MANUAL_IPS);
        let addedCount = 0;
        validIps.forEach(ip => {
          if (!existingIps.has(ip)) {
            currentKvConfig.MANUAL_IPS.push(ip);
            addedCount++;
          }
        });
        
        // 保存更新后的配置
        await WORKER_CONFIG.put('worker_config', JSON.stringify(currentKvConfig));
        
        await logMessage('info', 'IP筛选完成', {
          total_tested: ips.length,
          valid_ips: validIps.length,
          added_ips: addedCount,
          user: 'admin'
        });
        
        return new Response(JSON.stringify({
          success: true,
          message: `筛选完成：${validIps.length}个有效IP，${addedCount}个新增IP`,
          validIps: validIps.length,
          addedIps: addedCount,
          totalTested: ips.length,
          results: results
        }), {
          headers: { 'Content-Type': 'application/json' }
        });
        
      } catch (error) {
        await logMessage('error', 'IP筛选失败', { error: error.message });
        return new Response(JSON.stringify({ success: false, error: 'IP筛选失败：' + error.message }), {
          status: 500, headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // 主管理页面
    if (path === '/' && method === 'GET') {
      const isAuthenticated = await verifyAuth(request);
      if (!isAuthenticated) {
        return Response.redirect(new URL('/login', request.url), 302);
      }
      return new Response(await generateAdminPage(), {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }
    
    // 404处理
    return new Response(JSON.stringify({
      success: false,
      error: '页面未找到',
      path
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    await logPerformance('request_handling', duration, false, {
      path, method, client_ip: clientIP, error: error.message
    });
    
    await logMessage('error', 'request_error', {
      error: error.message,
      stack: error.stack,
      path, method, client_ip: clientIP
    }, requestId);

    const config = await getConfig();
    const errorResponse = {
      success: false,
      error: config.LOG_LEVEL === 'debug'
        ? `服务器内部错误: ${error.message}`
        : '服务器内部错误',
      requestId
    };

    if (config.LOG_LEVEL === 'debug') {
      errorResponse.stack = error.stack;
    }

    return new Response(JSON.stringify(errorResponse), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  } finally {
    const duration = Date.now() - startTime;
    await logPerformance('request_handling', duration, true, {
      path, method, client_ip: clientIP
    });
  }
}

async function generateAdminPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎛️ EdgeOne 优选IP - 配置管理</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f0f2f5; color: #333; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e8e8e8; padding-bottom: 20px; margin-bottom: 20px; }
        h1 { color: #1a1a1a; font-size: 24px; margin: 0; }
        .logout-btn { background: #ff4d4f; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: 500; transition: background 0.3s; }
        .logout-btn:hover { background: #d9363e; }
        .form-section { margin-bottom: 30px; }
        .form-section h2 { font-size: 18px; color: #333; border-bottom: 2px solid #667eea; padding-bottom: 8px; margin-bottom: 15px; }
        .form-grid { display: grid; grid-template-columns: 200px 1fr; gap: 15px 20px; align-items: center; }
        label { font-weight: 500; text-align: right; color: #555; }
        input[type="text"], input[type="number"], input[type="password"], textarea, select { width: 100%; padding: 10px; border-radius: 6px; border: 1px solid #d9d9d9; transition: border-color 0.3s, box-shadow 0.3s; }
        input:focus, textarea:focus, select:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 2px rgba(102, 126, 234, 0.2); }
        textarea { min-height: 120px; resize: vertical; }
        .btn-container { text-align: right; margin-top: 20px; }
        .save-btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: 600; transition: transform 0.2s; }
        .save-btn:hover { transform: translateY(-2px); }
        .form-group { display: contents; }
        .checkbox-label { display: flex; align-items: center; gap: 8px; text-align: left; }
        input[type="checkbox"] { width: auto; transform: scale(1.2); }
        #message { margin-top: 15px; padding: 12px; border-radius: 6px; text-align: center; display: none; }
        #message.success { background-color: #f6ffed; border: 1px solid #b7eb8f; color: #52c41a; }
        #message.error { background-color: #fff1f0; border: 1px solid #ffa39e; color: #f5222d; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎛️ EdgeOne 优选IP 配置管理</h1>
            <button id="logoutLink" class="logout-btn">注销</button>
        </div>
        <p>在这里修改您的Worker配置。注意：敏感信息（如API令牌和密码）通过环境变量设置，不会在此显示。</p>
        
        <form id="configForm">
            <div class="form-section">
                <h2>域名配置</h2>
                <div class="form-grid">
                    <label for="DOMAINS">域名 (JSON):</label>
                    <textarea id="DOMAINS" name="DOMAINS"></textarea>
                </div>
            </div>

            <div class="form-section">
                <h2>任务参数</h2>
                <div class="form-grid">
                    <label for="WEICE_URL">微测网URL:</label>
                    <input type="text" id="WEICE_URL" name="WEICE_URL">
                    <label for="MAX_IPS">最大IP数量:</label>
                    <input type="number" id="MAX_IPS" name="MAX_IPS">
                    <label for="TIMEOUT">超时时间 (ms):</label>
                    <input type="number" id="TIMEOUT" name="TIMEOUT">
                    <label for="UPDATE_INTERVAL">更新频率 (Cron):</label>
                    <input type="text" id="UPDATE_INTERVAL" name="UPDATE_INTERVAL">
                </div>
            </div>

            <div class="form-section">
                <h2>IP筛选</h2>
                <div class="form-grid">
                    <label for="MAX_LATENCY">最大延迟 (ms):</label>
                    <input type="number" id="MAX_LATENCY" name="FILTER_OPTIONS.MAX_LATENCY">
                    <label for="MIN_SPEED">最小速度 (kB/s):</label>
                    <input type="number" id="MIN_SPEED" name="FILTER_OPTIONS.MIN_SPEED">
                    <label for="MIN_BANDWIDTH">最小带宽 (MB):</label>
                    <input type="number" id="MIN_BANDWIDTH" name="FILTER_OPTIONS.MIN_BANDWIDTH">
                </div>
            </div>

            <div class="form-section">
                <h2>手动IP筛选</h2>
                <div class="form-grid">
                    <label for="MANUAL_IPS">IP列表:</label>
                    <textarea id="MANUAL_IPS" placeholder="请输入IP地址，每行一个，例如：&#10;1.1.1.1&#10;8.8.8.8&#10;208.67.222.222" style="min-height: 150px;"></textarea>
                    <label></label>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <button type="button" id="filterIpsBtn" class="save-btn" style="margin: 0;">筛选并添加IP</button>
                        <span id="filterStatus" style="color: #666; font-size: 14px;"></span>
                    </div>
                </div>
            </div>

            <div class="form-section">
                <h2>通知与日志</h2>
                <div class="form-grid">
                    <label for="ENABLE_LOGS">启用日志:</label>
                    <div class="checkbox-label"><input type="checkbox" id="ENABLE_LOGS" name="ENABLE_LOGS"></div>
                    <label for="ENABLE_NOTIFICATION">启用Telegram通知:</label>
                    <div class="checkbox-label"><input type="checkbox" id="ENABLE_NOTIFICATION" name="ENABLE_NOTIFICATION"></div>
                    <label for="NOTIFY_SUCCESS">成功时通知:</label>
                    <div class="checkbox-label"><input type="checkbox" id="NOTIFY_SUCCESS" name="NOTIFY_SUCCESS"></div>
                    <label for="NOTIFY_ERROR">失败时通知:</label>
                    <div class="checkbox-label"><input type="checkbox" id="NOTIFY_ERROR" name="NOTIFY_ERROR"></div>
                </div>
            </div>

            <div class="btn-container">
                <button type="submit" class="save-btn">保存配置</button>
            </div>
        </form>
        <div id="message"></div>
    </div>

    <script>
        const form = document.getElementById('configForm');
        const messageDiv = document.getElementById('message');

        function showMessage(msg, type) {
            messageDiv.textContent = msg;
            messageDiv.className = type;
            messageDiv.style.display = 'block';
            setTimeout(() => { messageDiv.style.display = 'none'; }, 5000);
        }

        async function loadConfig() {
            try {
                const response = await fetch('/api/config');
                const result = await response.json();
                if (result.success) {
                    const config = result.config;
                    form.DOMAINS.value = JSON.stringify(config.DOMAINS, null, 2);
                    form.WEICE_URL.value = config.WEICE_URL;
                    form.MAX_IPS.value = config.MAX_IPS;
                    form.TIMEOUT.value = config.TIMEOUT;
                    form.UPDATE_INTERVAL.value = config.UPDATE_INTERVAL;
                    if (config.FILTER_OPTIONS) {
                        form['FILTER_OPTIONS.MAX_LATENCY'].value = config.FILTER_OPTIONS.MAX_LATENCY;
                        form['FILTER_OPTIONS.MIN_SPEED'].value = config.FILTER_OPTIONS.MIN_SPEED;
                        form['FILTER_OPTIONS.MIN_BANDWIDTH'].value = config.FILTER_OPTIONS.MIN_BANDWIDTH;
                    }
                    form.ENABLE_LOGS.checked = config.ENABLE_LOGS;
                    form.ENABLE_NOTIFICATION.checked = config.ENABLE_NOTIFICATION;
                    form.NOTIFY_SUCCESS.checked = config.NOTIFY_SUCCESS;
                    form.NOTIFY_ERROR.checked = config.NOTIFY_ERROR;
                } else {
                    showMessage(result.error || '加载配置失败', 'error');
                }
            } catch (err) {
                showMessage('加载配置时发生网络错误', 'error');
            }
        }

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            try {
                const data = {
                    DOMAINS: JSON.parse(form.DOMAINS.value),
                    WEICE_URL: form.WEICE_URL.value,
                    MAX_IPS: parseInt(form.MAX_IPS.value),
                    TIMEOUT: parseInt(form.TIMEOUT.value),
                    UPDATE_INTERVAL: form.UPDATE_INTERVAL.value,
                    FILTER_OPTIONS: {
                        MAX_LATENCY: parseInt(form['FILTER_OPTIONS.MAX_LATENCY'].value),
                        MIN_SPEED: parseInt(form['FILTER_OPTIONS.MIN_SPEED'].value),
                        MIN_BANDWIDTH: parseInt(form['FILTER_OPTIONS.MIN_BANDWIDTH'].value),
                    },
                    ENABLE_LOGS: form.ENABLE_LOGS.checked,
                    ENABLE_NOTIFICATION: form.ENABLE_NOTIFICATION.checked,
                    NOTIFY_SUCCESS: form.NOTIFY_SUCCESS.checked,
                    NOTIFY_ERROR: form.NOTIFY_ERROR.checked,
                };

                const response = await fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                const result = await response.json();
                if (result.success) {
                    showMessage(result.message, 'success');
                } else {
                    showMessage(result.error || '保存失败', 'error');
                }
            } catch (err) {
                 if (err instanceof SyntaxError) {
                    showMessage('域名JSON格式错误，请检查。', 'error');
                } else {
                    showMessage('保存配置时发生错误: ' + err.message, 'error');
                }
            }
        });

        document.getElementById('logoutLink').addEventListener('click', async (e) => {
            e.preventDefault();
            const response = await fetch('/api/auth/logout', { method: 'POST' });
            const result = await response.json();
            if (result.success) {
                window.location.href = '/login';
            } else {
                showMessage('注销失败', 'error');
            }
        });

        document.getElementById('filterIpsBtn').addEventListener('click', async (e) => {
            e.preventDefault();
            const manualIpsTextarea = document.getElementById('MANUAL_IPS');
            const filterStatus = document.getElementById('filterStatus');
            const ipsText = manualIpsTextarea.value.trim();
            
            if (!ipsText) {
                showMessage('请输入要筛选的IP地址', 'error');
                return;
            }
            
            // 解析IP列表
            const ipList = ipsText.split('\n')
                .map(ip => ip.trim())
                .filter(ip => ip && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip));
            
            if (ipList.length === 0) {
                showMessage('没有找到有效的IP地址格式', 'error');
                return;
            }
            
filterStatus.textContent = '正在筛选 ' + ipList.length + ' 个IP...';
            document.getElementById('filterIpsBtn').disabled = true;
            try {
                const response = await fetch('/api/filter-ips', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips: ipList })
                });
                const result = await response.json();
                if (result.success) {
                    filterStatus.textContent = \`筛选完成：${result.validIps} 个有效IP，${result.addedIps} 个已添加\`;
                    showMessage(\`IP筛选完成！有效IP: ${result.validIps}个，已添加: ${result.addedIps}个\`, 'success');
                    manualIpsTextarea.value = '';
                } else {
                    filterStatus.textContent = '筛选失败';
                    showMessage(result.error || 'IP筛选失败', 'error');
                }
            } catch (err) {
                filterStatus.textContent = '筛选失败';
                showMessage('筛选IP时发生网络错误: ' + err.message, 'error');
            } finally {
                document.getElementById('filterIpsBtn').disabled = false;
            }
        });

        loadConfig();
    </script>
</body>
</html>`;
}

// Worker导出
export default {
  async fetch(request, env, ctx) {
    // 设置全局环境变量
    Object.assign(globalThis, env);
    
    return handleRequest(request);
  }
};

