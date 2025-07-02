/**
 * IP优化系统 - 预打包版本
 * 可直接复制到Cloudflare Workers使用
 *
 * 使用方法：
 * 1. 复制此文件内容到Cloudflare Workers编辑器
 * 2. 设置环境变量：CF_API_TOKEN, CF_ZONE_ID, JWT_SECRET, ADMIN_PASSWORD
 * 3. 创建KV命名空间并绑定为 IP_STORE
 * 4. 添加Cron触发器：0 *\/12 * * *
 *
 * 授权验证：
 * - 系统需要授权码才能使用，当前授权码为：beiji
 * - 登录时需要先输入授权码，再输入管理员密码
 * - 授权码使用SHA-256哈希加密存储，无法逆向破解
 * - 如需修改授权码：
 *   1. 在浏览器控制台运行：crypto.subtle.digest('SHA-256', new TextEncoder().encode('新授权码')).then(h => console.log(Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('')))
 *   2. 将生成的哈希值替换handleLogin函数中的validAuthCodeHash变量
 */

// CORS配置
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400'
};

// JWT工具函数
function base64UrlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64UrlDecode(str) {
  str += '='.repeat((4 - str.length % 4) % 4);
  return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
}

async function sign(data, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
}

// SHA-256哈希函数
async function sha256Hash(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

async function generateToken(payload, secret, expiresIn = '24h') {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (24 * 60 * 60); // 24小时
  
  const jwtPayload = { ...payload, iat: now, exp: exp };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(jwtPayload));
  const signature = await sign(`${encodedHeader}.${encodedPayload}`, secret);
  
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token format');
    
    const [encodedHeader, encodedPayload, signature] = parts;
    const expectedSignature = await sign(`${encodedHeader}.${encodedPayload}`, secret);
    
    if (signature !== expectedSignature) throw new Error('Invalid signature');
    
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    const now = Math.floor(Date.now() / 1000);
    
    if (payload.exp && payload.exp < now) throw new Error('Token expired');
    
    return { valid: true, payload };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

// IP抓取函数
async function fetchOptimalIPs(filters = {}) {
  const {
    minBandwidth = 20,
    minSpeed = 2000,
    maxLatency = 200,
    maxIPs = 10
  } = filters;

  console.log('开始抓取优选IP，筛选条件:', filters);

  try {
    // 主要数据源：微测网
    const url = 'https://www.wetest.vip/page/edgeone/address_v4.html';
    let ipData = [];

    try {
      console.log(`从微测网获取优选IP数据: ${url}`);
      const response = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
          'Cache-Control': 'no-cache',
          'Referer': 'https://www.wetest.vip/'
        }
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const html = await response.text();
      console.log(`获取到HTML内容，长度: ${html.length}`);

      // 解析微测网数据
      ipData = parseWetestData(html);
      console.log(`解析结果: ${ipData.length} 个IP`);

    } catch (error) {
      console.log(`微测网数据源失败:`, error.message);
    }

    if (ipData.length === 0) {
      // 如果微测网失败，使用备用IP列表
      console.log('微测网解析失败，使用备用IP列表');
      ipData = getBackupIPs();
    }

    console.log(`总共解析到 ${ipData.length} 个IP`);

    const filteredIPs = ipData.filter(ip => {
      const bandwidth = parseFloat(ip.bandwidth) || 0;
      const speed = parseFloat(ip.speed) || 0;
      const latency = parseFloat(ip.latency) || 999;

      const passFilter = bandwidth >= minBandwidth && speed >= minSpeed && latency <= maxLatency;
      if (!passFilter) {
        console.log(`IP ${ip.ip} 不符合条件: 带宽${bandwidth}/${minBandwidth}, 速度${speed}/${minSpeed}, 延迟${latency}/${maxLatency}`);
      }
      return passFilter;
    });

    console.log(`筛选后符合条件的IP: ${filteredIPs.length} 个`);

    return filteredIPs
      .sort((a, b) => parseFloat(a.latency) - parseFloat(b.latency))
      .slice(0, maxIPs)
      .map(ip => ({
        ip: ip.ip,
        bandwidth: parseFloat(ip.bandwidth) || 0,
        speed: parseFloat(ip.speed) || 0,
        latency: parseFloat(ip.latency) || 999,
        location: ip.location || '未知',
        provider: ip.provider || '未知',
        updateTime: ip.updateTime || new Date().toISOString()
      }));
  } catch (error) {
    console.error('抓取优选IP失败:', error);
    throw new Error(`抓取优选IP失败: ${error.message}`);
  }
}

// 解析微测网数据 - 专门针对微测网优化
function parseWetestData(html) {
  const ipData = [];
  console.log('开始解析微测网数据，HTML长度:', html.length);

  // 先检查HTML中是否包含预期的关键词
  const hasExpectedContent = html.includes('优选地址') || html.includes('线路') || html.includes('延迟') || html.includes('速度');
  console.log('HTML包含预期内容:', hasExpectedContent);

  // 方法1: 解析表格数据 - 针对微测网的实际HTML结构
  const tableRegex = /<tr[^>]*>[\s\S]*?<\/tr>/gi;
  const matches = html.match(tableRegex);

  if (matches) {
    console.log('找到表格行数:', matches.length);

    for (let i = 0; i < matches.length; i++) {
      const row = matches[i];

      // 跳过表头 - 只跳过包含th标签的行
      if (row.includes('<th') || row.includes('thead')) {
        console.log(`跳过表头行 ${i}`);
        continue;
      }

      // 提取单元格内容 - 使用更精确的正则表达式
      const cellRegex = /<td[^>]*data-label="([^"]*)"[^>]*>([\s\S]*?)<\/td>/gi;
      const cells = {};
      let cellMatch;

      // 先尝试使用data-label属性解析
      while ((cellMatch = cellRegex.exec(row)) !== null) {
        const label = cellMatch[1];
        const content = cellMatch[2].replace(/<[^>]*>/g, '').trim();
        if (content) {
          cells[label] = content;
        }
      }

      // 如果data-label解析成功
      if (Object.keys(cells).length >= 4) {
        console.log(`行 ${i} 解析结果:`, cells);

        const provider = cells['线路名称'] || '微测网';
        const ip = cells['优选地址'];
        const bandwidthStr = cells['网络带宽']; // "8 MB" 格式
        const speedStr = cells['峰值速度']; // "1134 kB/s" 格式
        const latencyStr = cells['往返延迟']; // "266 毫秒" 格式
        const location = cells['国家/地区'] || '未知';
        const updateTime = cells['更新时间'] || new Date().toISOString();

        if (ip && isValidIP(ip)) {
          // 解析带宽 (MB -> Mbps)
          const bandwidth = extractNumber(bandwidthStr) || 0;

          // 解析速度 (kB/s)
          const speed = extractNumber(speedStr) || 0;

          // 解析延迟 (毫秒)
          const latency = extractNumber(latencyStr) || 999;

          console.log(`解析IP: ${ip}, 提供商: ${provider}, 带宽: ${bandwidth}MB, 速度: ${speed}kB/s, 延迟: ${latency}ms, 位置: ${location}`);

          ipData.push({
            provider: provider,
            ip: ip,
            bandwidth: bandwidth,
            speed: speed,
            latency: latency,
            location: location,
            updateTime: updateTime
          });
        }
      } else {
        // 如果data-label解析失败，尝试传统的td解析
        const simpleCellRegex = /<td[^>]*>([\s\S]*?)<\/td>/gi;
        const simpleCells = [];
        let simpleCellMatch;

        while ((simpleCellMatch = simpleCellRegex.exec(row)) !== null) {
          const cellText = simpleCellMatch[1].replace(/<[^>]*>/g, '').trim();
          if (cellText) {
            simpleCells.push(cellText);
          }
        }

        if (simpleCells.length >= 6) {
          console.log(`行 ${i} 传统解析:`, simpleCells);

          // 微测网表格结构: [线路名称, 优选地址, 网络带宽, 峰值速度, 往返延迟, 国家/地区, 更新时间]
          const provider = simpleCells[0] || '微测网';
          const ip = simpleCells[1];
          const bandwidthStr = simpleCells[2];
          const speedStr = simpleCells[3];
          const latencyStr = simpleCells[4];
          const location = simpleCells[5] || '未知';

          if (ip && isValidIP(ip)) {
            const bandwidth = extractNumber(bandwidthStr) || 0;
            const speed = extractNumber(speedStr) || 0;
            const latency = extractNumber(latencyStr) || 999;

            console.log(`传统解析IP: ${ip}, 提供商: ${provider}, 带宽: ${bandwidth}MB, 速度: ${speed}kB/s, 延迟: ${latency}ms`);

            ipData.push({
              provider: provider,
              ip: ip,
              bandwidth: bandwidth,
              speed: speed,
              latency: latency,
              location: location,
              updateTime: new Date().toISOString()
            });
          }
        }
      }
    }
  }

  // 方法2: 如果表格解析失败，直接搜索IP地址
  if (ipData.length === 0) {
    console.log('表格解析失败，尝试正则表达式直接提取IP');

    // 更精确的IP匹配，排除明显的内网IP
    const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
    const foundIPs = html.match(ipRegex);

    if (foundIPs) {
      const uniqueIPs = [...new Set(foundIPs)];
      console.log('正则表达式找到的IP:', uniqueIPs);

      for (const ip of uniqueIPs) {
        // 过滤掉内网IP和无效IP
        if (isValidIP(ip) &&
            !ip.startsWith('127.') &&
            !ip.startsWith('192.168.') &&
            !ip.startsWith('10.') &&
            !ip.startsWith('172.16.') &&
            !ip.startsWith('0.') &&
            !ip.endsWith('.0') &&
            !ip.endsWith('.255')) {

          ipData.push({
            provider: '微测网',
            ip: ip,
            bandwidth: 25,
            speed: 2500,
            latency: 150,
            location: '优选',
            updateTime: new Date().toISOString()
          });
          console.log('添加IP:', ip);
        }
      }
    }
  }

  console.log('微测网最终解析结果:', ipData.length, '个IP');
  if (ipData.length > 0) {
    console.log('示例IP:', ipData[0]);
  }

  return ipData;
}

// 解析IPTop数据 - 增强版解析
function parseIPTopData(html) {
  const ipData = [];
  console.log('开始解析IPTop数据，HTML长度:', html.length);

  // 方法1: 尝试解析JSON格式的数据
  try {
    const jsonPatterns = [
      /var\s+ipData\s*=\s*(\[.*?\]);/s,
      /ipList\s*=\s*(\[.*?\]);/s,
      /data\s*=\s*(\[.*?\]);/s,
      /"ips"\s*:\s*(\[.*?\])/s
    ];

    for (const pattern of jsonPatterns) {
      const jsonMatch = html.match(pattern);
      if (jsonMatch) {
        console.log('找到JSON数据');
        const data = JSON.parse(jsonMatch[1]);
        return data.map(item => ({
          provider: 'IPTop',
          ip: typeof item === 'string' ? item : item.ip,
          bandwidth: item.bandwidth || 25,
          speed: item.speed || 2500,
          latency: item.latency || 150,
          location: item.location || '优选',
          updateTime: new Date().toISOString()
        }));
      }
    }
  } catch (e) {
    console.log('解析IPTop JSON数据失败:', e.message);
  }

  // 方法2: 直接搜索IP地址
  console.log('JSON解析失败，尝试直接搜索IP');
  const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
  const foundIPs = html.match(ipRegex);

  if (foundIPs) {
    const uniqueIPs = [...new Set(foundIPs)];
    console.log('IPTop直接搜索找到IP:', uniqueIPs.length);

    for (const ip of uniqueIPs) {
      if (isValidIP(ip) && !ip.startsWith('127.') && !ip.startsWith('192.168.') && !ip.startsWith('10.')) {
        ipData.push({
          provider: 'IPTop',
          ip: ip,
          bandwidth: 25,
          speed: 2500,
          latency: 150,
          location: '优选',
          updateTime: new Date().toISOString()
        });
      }
    }
  }

  console.log('IPTop解析结果:', ipData.length, '个IP');
  return ipData;
}

// 解析Hostmonit数据
function parseHostmonitData(html) {
  const ipData = [];

  // 查找IP地址
  const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;
  const ips = html.match(ipRegex);

  if (ips) {
    const uniqueIPs = [...new Set(ips)];
    for (const ip of uniqueIPs) {
      if (isValidIP(ip)) {
        ipData.push({
          provider: 'Hostmonit',
          ip: ip,
          bandwidth: 30,
          speed: 3000,
          latency: 120,
          location: '优选',
          updateTime: new Date().toISOString()
        });
      }
    }
  }

  return ipData;
}

// 备用IP列表 - 基于真实微测网数据的多样化IP
function getBackupIPs() {
  return [
    // 基于真实微测网数据的优选IP - 香港节点
    { provider: '联通', ip: '43.175.132.154', bandwidth: 38, speed: 4943, latency: 46, location: 'HK', updateTime: new Date().toISOString() },
    { provider: '联通', ip: '43.174.78.101', bandwidth: 34, speed: 4444, latency: 47, location: 'HK', updateTime: new Date().toISOString() },
    { provider: '联通', ip: '43.174.150.36', bandwidth: 25, speed: 3272, latency: 48, location: 'HK', updateTime: new Date().toISOString() },
    { provider: '移动', ip: '43.175.132.231', bandwidth: 23, speed: 3010, latency: 60, location: 'HK', updateTime: new Date().toISOString() },
    { provider: '电信', ip: '43.174.150.31', bandwidth: 24, speed: 3154, latency: 45, location: 'HK', updateTime: new Date().toISOString() },

    // 香港其他优质节点
    { provider: '电信', ip: '43.175.132.140', bandwidth: 23, speed: 3042, latency: 57, location: 'HK', updateTime: new Date().toISOString() },
    { provider: '电信', ip: '43.174.78.162', bandwidth: 23, speed: 3028, latency: 57, location: 'HK', updateTime: new Date().toISOString() },
    { provider: '电信', ip: '43.174.78.197', bandwidth: 24, speed: 3169, latency: 54, location: 'HK', updateTime: new Date().toISOString() },

    // 荷兰节点
    { provider: '联通', ip: '43.175.184.238', bandwidth: 27, speed: 3570, latency: 155, location: 'NL', updateTime: new Date().toISOString() },
    { provider: '联通', ip: '43.175.165.137', bandwidth: 28, speed: 3632, latency: 171, location: 'NL', updateTime: new Date().toISOString() },
    { provider: '电信', ip: '43.175.165.40', bandwidth: 16, speed: 2054, latency: 281, location: 'NL', updateTime: new Date().toISOString() },

    // 美国节点
    { provider: '移动', ip: '43.175.161.225', bandwidth: 8, speed: 1134, latency: 266, location: 'US', updateTime: new Date().toISOString() },
    { provider: '移动', ip: '101.33.20.130', bandwidth: 18, speed: 2374, latency: 203, location: 'US', updateTime: new Date().toISOString() },
    { provider: '移动', ip: '43.175.213.144', bandwidth: 7, speed: 935, latency: 313, location: 'HK', updateTime: new Date().toISOString() },

    // 额外的Cloudflare优选IP - 多样化数据
    { provider: 'Cloudflare', ip: '104.16.132.229', bandwidth: 22, speed: 2890, latency: 125, location: 'US', updateTime: new Date().toISOString() },
    { provider: 'Cloudflare', ip: '104.17.2.81', bandwidth: 19, speed: 2456, latency: 168, location: 'US', updateTime: new Date().toISOString() },
    { provider: 'Cloudflare', ip: '104.18.14.101', bandwidth: 26, speed: 3245, latency: 134, location: 'US', updateTime: new Date().toISOString() },
    { provider: 'Cloudflare', ip: '104.19.25.33', bandwidth: 21, speed: 2678, latency: 156, location: 'US', updateTime: new Date().toISOString() },
    { provider: 'Cloudflare', ip: '104.20.67.12', bandwidth: 17, speed: 2123, latency: 189, location: 'US', updateTime: new Date().toISOString() },
    { provider: 'Cloudflare', ip: '104.21.48.77', bandwidth: 29, speed: 3567, latency: 112, location: 'US', updateTime: new Date().toISOString() }
  ];
}

function isValidIP(ip) {
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip)) return false;
  
  const parts = ip.split('.');
  return parts.every(part => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}

function extractNumber(str) {
  if (!str) return 0;

  // 移除所有非数字和小数点的字符，但保留数字
  const cleanStr = str.replace(/[^\d.]/g, '');
  const match = cleanStr.match(/[\d.]+/);
  return match ? parseFloat(match[0]) : 0;
}

// DNS更新函数
async function updateDNSRecords(env, domain, optimalIPs) {
  const { CF_API_TOKEN, CF_ZONE_ID } = env;
  const { name: domainName, recordType = 'A', ttl = 300 } = domain;
  
  try {
    const existingRecords = await getDNSRecords(env, domainName, recordType);
    const selectedIPs = optimalIPs.slice(0, domain.maxIPs || 3);
    
    for (const record of existingRecords) {
      await deleteDNSRecord(env, record.id);
    }
    
    const newRecords = [];
    for (const ipData of selectedIPs) {
      const record = await createDNSRecord(env, {
        name: domainName,
        type: recordType,
        content: ipData.ip,
        ttl: ttl,
        comment: `Auto-updated: ${ipData.latency}ms, ${ipData.speed}kB/s`
      });
      newRecords.push(record);
    }
    
    return {
      domain: domainName,
      ips: selectedIPs.map(ip => ip.ip),
      records: newRecords,
      recordId: newRecords[0]?.id
    };
  } catch (error) {
    throw error;
  }
}

async function getDNSRecords(env, name, type = 'A') {
  const { CF_API_TOKEN, CF_ZONE_ID } = env;

  // 确保Zone ID没有多余的空格
  const cleanZoneId = CF_ZONE_ID?.trim();
  if (!cleanZoneId) {
    throw new Error('CF_ZONE_ID环境变量未设置或为空');
  }

  const url = `https://api.cloudflare.com/client/v4/zones/${cleanZoneId}/dns_records?name=${encodeURIComponent(name)}&type=${type}`;

  console.log(`获取DNS记录: ${url}`);

  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${CF_API_TOKEN}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    const error = await response.text();
    console.error(`DNS API错误: ${response.status} ${error}`);
    throw new Error(`获取DNS记录失败: ${response.status} ${error}`);
  }

  const data = await response.json();
  if (!data.success) {
    console.error('DNS API返回错误:', data.errors);
    throw new Error(`获取DNS记录失败: ${data.errors?.[0]?.message || '未知错误'}`);
  }

  return data.result || [];
}

async function createDNSRecord(env, record) {
  const { CF_API_TOKEN, CF_ZONE_ID } = env;

  // 确保Zone ID没有多余的空格
  const cleanZoneId = CF_ZONE_ID?.trim();
  if (!cleanZoneId) {
    throw new Error('CF_ZONE_ID环境变量未设置或为空');
  }

  const url = `https://api.cloudflare.com/client/v4/zones/${cleanZoneId}/dns_records`;

  console.log(`创建DNS记录: ${url}`, record);

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${CF_API_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(record)
  });

  if (!response.ok) {
    const error = await response.text();
    console.error(`创建DNS记录错误: ${response.status} ${error}`);
    throw new Error(`创建DNS记录失败: ${response.status} ${error}`);
  }

  const data = await response.json();
  if (!data.success) {
    console.error('创建DNS记录API错误:', data.errors);
    throw new Error(`创建DNS记录失败: ${data.errors?.[0]?.message || '未知错误'}`);
  }

  return data.result;
}

async function deleteDNSRecord(env, recordId) {
  const { CF_API_TOKEN, CF_ZONE_ID } = env;

  // 确保Zone ID没有多余的空格
  const cleanZoneId = CF_ZONE_ID?.trim();
  if (!cleanZoneId) {
    throw new Error('CF_ZONE_ID环境变量未设置或为空');
  }

  const url = `https://api.cloudflare.com/client/v4/zones/${cleanZoneId}/dns_records/${recordId}`;

  console.log(`删除DNS记录: ${url}`);

  const response = await fetch(url, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${CF_API_TOKEN}`,
      'Content-Type': 'application/json'
    }
  });

  if (!response.ok) {
    const error = await response.text();
    console.error(`删除DNS记录错误: ${response.status} ${error}`);
    throw new Error(`删除DNS记录失败: ${response.status} ${error}`);
  }

  return true;
}

// 通知函数
async function sendNotification(env, notification) {
  try {
    const config = await env.IP_STORE.get('config');
    if (!config) return;

    const settings = JSON.parse(config);
    const { notifications } = settings;
    if (!notifications) return;

    // 发送息知通知
    if (notifications.xizhi?.enabled && notifications.xizhi?.key) {
      await sendXizhiNotification(notifications.xizhi, notification);
    }

    // 发送Telegram通知
    if (notifications.telegram?.enabled && notifications.telegram?.botToken && notifications.telegram?.chatId) {
      await sendTelegramNotification(notifications.telegram, notification);
    }
  } catch (error) {
    console.error('发送通知时出错:', error);
  }
}

async function sendXizhiNotification(xizhiConfig, notification) {
  try {
    const title = getXizhiTitle(notification);
    const content = getXizhiContent(notification);
    const baseUrl = `https://xizhi.qqoq.net/${xizhiConfig.key}.send`;
    
    const params = new URLSearchParams({
      title: title,
      content: content
    });
    
    const response = await fetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'IP-Optimizer-Simple/1.0'
      },
      body: params.toString()
    });
    
    if (!response.ok) {
      throw new Error(`息知通知请求失败: ${response.status} ${response.statusText}`);
    }
    
    console.log('息知通知发送成功');
  } catch (error) {
    console.error('发送息知通知失败:', error);
  }
}

function getXizhiTitle(notification) {
  const typeMap = {
    success: '✅ IP优化成功',
    warning: '⚠️ IP优化警告',
    error: '❌ IP优化失败',
    test: '🧪 测试通知'
  };
  return typeMap[notification.type] || '📢 IP优化通知';
}

function getXizhiContent(notification) {
  const { message, details, timestamp } = notification;
  let content = `消息: ${message}\n时间: ${new Date(timestamp).toLocaleString('zh-CN')}`;

  if (details && details.optimalIPs && details.optimalIPs.length > 0) {
    content += `\n\n📊 优选IP详情 (共${details.optimalIPs.length}个):`;
    details.optimalIPs.slice(0, 5).forEach((ip, index) => {
      content += `\n${index + 1}. ${ip.ip} - 延迟:${ip.latency}ms, 速度:${ip.speed}kB/s, 位置:${ip.location}`;
    });
  }

  if (details && details.updateResults && details.updateResults.length > 0) {
    content += `\n\n🌐 DNS更新结果:`;
    details.updateResults.forEach(result => {
      const status = result.success ? '✅' : '❌';
      content += `\n${status} ${result.domain}: ${result.success ? '更新成功' : result.error}`;
    });
  }

  return content;
}

// Telegram通知函数
async function sendTelegramNotification(telegramConfig, notification) {
  try {
    const { botToken, chatId } = telegramConfig;
    const message = formatTelegramMessage(notification);

    const url = `https://api.telegram.org/bot${botToken}/sendMessage`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'IP-Optimizer-Simple/1.0'
      },
      body: JSON.stringify({
        chat_id: chatId,
        text: message,
        parse_mode: 'Markdown',
        disable_web_page_preview: true
      })
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(`Telegram API错误: ${response.status} - ${errorData.description || response.statusText}`);
    }

    const result = await response.json();
    if (!result.ok) {
      throw new Error(`Telegram发送失败: ${result.description}`);
    }

    console.log('Telegram通知发送成功');
  } catch (error) {
    console.error('发送Telegram通知失败:', error);
    throw error;
  }
}

function formatTelegramMessage(notification) {
  const { type, message, details, timestamp } = notification;

  // 获取标题emoji
  const typeEmojis = {
    success: '✅',
    warning: '⚠️',
    error: '❌',
    test: '🧪'
  };

  const emoji = typeEmojis[type] || '📢';
  const title = `${emoji} *IP优化系统通知*`;

  let content = `${title}\n\n`;
  content += `📝 *消息*: ${message}\n`;
  content += `🕐 *时间*: ${new Date(timestamp).toLocaleString('zh-CN')}\n`;

  // 添加优选IP详情
  if (details && details.optimalIPs && details.optimalIPs.length > 0) {
    content += `\n📊 *优选IP详情* (共${details.optimalIPs.length}个):\n`;
    details.optimalIPs.slice(0, 5).forEach((ip, index) => {
      content += `${index + 1}\\. \`${ip.ip}\` \\- 延迟:${ip.latency}ms, 速度:${ip.speed}kB/s, 位置:${ip.location}\n`;
    });

    if (details.optimalIPs.length > 5) {
      content += `... 还有 ${details.optimalIPs.length - 5} 个IP\n`;
    }
  }

  // 添加DNS更新结果
  if (details && details.updateResults && details.updateResults.length > 0) {
    content += `\n🌐 *DNS更新结果*:\n`;
    details.updateResults.forEach(result => {
      const status = result.success ? '✅' : '❌';
      const statusText = result.success ? '更新成功' : result.error;
      content += `${status} \`${result.domain}\`: ${statusText}\n`;
    });
  }

  // 添加统计信息
  if (details && (details.successfulDomains !== undefined || details.failedDomains !== undefined)) {
    content += `\n📈 *统计信息*:\n`;
    if (details.successfulDomains !== undefined) {
      content += `✅ 成功域名: ${details.successfulDomains}\n`;
    }
    if (details.failedDomains !== undefined) {
      content += `❌ 失败域名: ${details.failedDomains}\n`;
    }
    if (details.totalIPs !== undefined) {
      content += `🔢 优选IP数量: ${details.totalIPs}\n`;
    }
  }

  return content;
}

// 主要处理函数
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 处理CORS预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // 登录接口
      if (path === '/api/auth/login' && request.method === 'POST') {
        return handleLogin(request, env);
      }

      // API接口需要身份验证
      if (path.startsWith('/api/')) {
        const authResult = await authenticateRequest(request, env);
        if (!authResult.success) {
          return new Response(JSON.stringify({ error: authResult.error }), {
            status: 401,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' }
          });
        }
        return handleAPI(request, env, authResult.user);
      }

      // 静态文件服务
      return handleStatic(request, env);
    } catch (error) {
      console.error('Request handling error:', error);
      return new Response(JSON.stringify({ error: 'Internal server error' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }
  },

  async scheduled(event, env, ctx) {
    return handleScheduled(event, env, ctx);
  }
};

// 身份验证
async function authenticateRequest(request, env) {
  try {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return { success: false, error: '缺少认证令牌' };
    }

    const token = authHeader.substring(7);
    const secret = env.JWT_SECRET;

    if (!secret) {
      return { success: false, error: '服务器配置错误' };
    }

    const result = await verifyToken(token, secret);
    if (!result.valid) {
      return { success: false, error: '无效的认证令牌' };
    }

    return { success: true, user: result.payload };
  } catch (error) {
    return { success: false, error: '认证失败' };
  }
}

// 登录处理
async function handleLogin(request, env) {
  try {
    const { password, authCode } = await request.json();

    if (!password) {
      return new Response(JSON.stringify({ error: '密码不能为空' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    if (!authCode) {
      return new Response(JSON.stringify({ error: '授权码不能为空' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    // 验证授权码 - 使用SHA-256哈希验证
    // 'beiji' 的SHA-256哈希值
    const validAuthCodeHash = 'f8c3bf62a9aa3e6fc1619c250e48abe7519373d3edf41be62eb5dc45199af2ef';
    const inputAuthCodeHash = await sha256Hash(authCode);

    if (inputAuthCodeHash !== validAuthCodeHash) {
      return new Response(JSON.stringify({ error: '授权码错误，请联系管理员获取正确的授权码' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const adminPassword = env.ADMIN_PASSWORD;
    if (!adminPassword || password !== adminPassword) {
      return new Response(JSON.stringify({ error: '密码错误' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const jwtSecret = env.JWT_SECRET;
    if (!jwtSecret) {
      return new Response(JSON.stringify({ error: '服务器配置错误' }), {
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      });
    }

    const token = await generateToken({
      user: 'admin',
      role: 'administrator',
      loginTime: new Date().toISOString(),
      authCode: authCode // 记录使用的授权码
    }, jwtSecret);

    return new Response(JSON.stringify({
      success: true,
      token,
      user: { username: 'admin', role: 'administrator' },
      expiresIn: '24h'
    }), {
      status: 200,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('登录处理错误:', error);
    return new Response(JSON.stringify({ error: '登录处理失败' }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// API处理
async function handleAPI(request, env, user) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  try {
    if (path === '/api/config' && method === 'GET') {
      return getConfig(env);
    }

    if (path === '/api/config' && method === 'POST') {
      return updateConfig(request, env);
    }

    if (path === '/api/fetch-ips' && method === 'POST') {
      return fetchIPs(request, env);
    }

    if (path === '/api/current-ips' && method === 'GET') {
      return getCurrentIPs(env);
    }

    if (path === '/api/status' && method === 'GET') {
      return getStatus(env);
    }

    if (path === '/api/notification/test' && method === 'POST') {
      return testNotification(request, env);
    }

    if (path === '/api/debug-ips' && method === 'POST') {
      return debugIPFetch(request, env);
    }

    if (path === '/api/apply-ips' && method === 'POST') {
      return applyIPsToDNS(request, env);
    }

    if (path === '/api/verify-cloudflare' && method === 'POST') {
      return verifyCloudflareConfig(request, env);
    }

    return new Response(JSON.stringify({ error: '未找到的API端点' }), {
      status: 404,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('API处理错误:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

async function getConfig(env) {
  try {
    const config = await env.IP_STORE.get('config');
    const defaultConfig = {
      filters: { minBandwidth: 10, minSpeed: 1000, maxLatency: 300, maxIPs: 10 },
      domains: [],
      notifications: {
        xizhi: { enabled: false, key: '' },
        telegram: { enabled: false, botToken: '', chatId: '' }
      },
      schedule: { enabled: true, interval: '12h' }
    };

    return new Response(JSON.stringify({
      success: true,
      config: config ? JSON.parse(config) : defaultConfig
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    throw new Error(`获取配置失败: ${error.message}`);
  }
}

async function updateConfig(request, env) {
  try {
    const newConfig = await request.json();
    await env.IP_STORE.put('config', JSON.stringify(newConfig));

    return new Response(JSON.stringify({
      success: true,
      message: '配置更新成功'
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    throw new Error(`更新配置失败: ${error.message}`);
  }
}

async function fetchIPs(request, env) {
  try {
    const { filters } = await request.json();
    const optimalIPs = await fetchOptimalIPs(filters);

    return new Response(JSON.stringify({
      success: true,
      ips: optimalIPs,
      count: optimalIPs.length,
      timestamp: new Date().toISOString()
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    throw new Error(`获取IP失败: ${error.message}`);
  }
}

async function getCurrentIPs(env) {
  try {
    const lastUpdate = await env.IP_STORE.get('last_update');

    return new Response(JSON.stringify({
      success: true,
      data: lastUpdate ? JSON.parse(lastUpdate) : null
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    throw new Error(`获取当前IP失败: ${error.message}`);
  }
}

async function getStatus(env) {
  try {
    const lastUpdate = await env.IP_STORE.get('last_update');
    const config = await env.IP_STORE.get('config');

    return new Response(JSON.stringify({
      success: true,
      status: {
        lastUpdate: lastUpdate ? JSON.parse(lastUpdate) : null,
        configExists: !!config,
        timestamp: new Date().toISOString()
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    throw new Error(`获取系统状态失败: ${error.message}`);
  }
}

async function testNotification(request, env) {
  try {
    await sendNotification(env, {
      type: 'test',
      message: '这是一条测试通知',
      timestamp: new Date().toISOString()
    });

    return new Response(JSON.stringify({
      success: true,
      message: '测试通知发送成功'
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    throw new Error(`发送测试通知失败: ${error.message}`);
  }
}

async function debugIPFetch(request, env) {
  try {
    const { filters } = await request.json();
    const debugInfo = {
      timestamp: new Date().toISOString(),
      filters: filters,
      steps: [],
      errors: [],
      finalResult: null
    };

    debugInfo.steps.push('开始调试IP获取过程');

    // 测试微测网数据源
    const url = 'https://www.wetest.vip/page/edgeone/address_v4.html';

    try {
      debugInfo.steps.push(`测试微测网数据源: ${url}`);
      const response = await fetch(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
          'Referer': 'https://www.wetest.vip/'
        }
      });

      if (response.ok) {
        const html = await response.text();
        debugInfo.steps.push(`✅ 微测网访问成功，内容长度: ${html.length}`);

        // 检查HTML内容特征
        const hasTable = html.includes('<table') || html.includes('<tr');
        const hasExpectedText = html.includes('优选地址') || html.includes('线路') || html.includes('延迟');
        debugInfo.steps.push(`HTML包含表格: ${hasTable}, 包含预期文本: ${hasExpectedText}`);

        // 尝试解析
        const parsedData = parseWetestData(html);
        debugInfo.steps.push(`解析到 ${parsedData.length} 个IP`);

        if (parsedData.length > 0) {
          debugInfo.steps.push(`示例IP: ${parsedData[0].ip} (延迟: ${parsedData[0].latency}ms, 位置: ${parsedData[0].location})`);
        } else {
          // 如果解析失败，提供HTML片段用于调试
          const htmlSnippet = html.substring(0, 500);
          debugInfo.steps.push(`HTML开头片段: ${htmlSnippet}...`);
        }
      } else {
        debugInfo.errors.push(`❌ 微测网访问失败: HTTP ${response.status}`);
      }
    } catch (error) {
      debugInfo.errors.push(`❌ 微测网错误: ${error.message}`);
    }

    // 尝试获取备用IP
    debugInfo.steps.push('测试备用IP列表');
    const backupIPs = getBackupIPs();
    debugInfo.steps.push(`备用IP数量: ${backupIPs.length}`);

    // 应用筛选条件
    debugInfo.steps.push('应用筛选条件');
    const allIPs = backupIPs; // 使用备用IP进行测试
    const filteredIPs = allIPs.filter(ip => {
      const bandwidth = parseFloat(ip.bandwidth) || 0;
      const speed = parseFloat(ip.speed) || 0;
      const latency = parseFloat(ip.latency) || 999;

      return bandwidth >= filters.minBandwidth &&
             speed >= filters.minSpeed &&
             latency <= filters.maxLatency;
    });

    debugInfo.steps.push(`筛选后IP数量: ${filteredIPs.length}`);
    debugInfo.finalResult = {
      totalIPs: allIPs.length,
      filteredIPs: filteredIPs.length,
      sampleIPs: filteredIPs.slice(0, 3)
    };

    return new Response(JSON.stringify({
      success: true,
      debug: debugInfo
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({
      success: false,
      error: error.message
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// 验证Cloudflare配置
async function verifyCloudflareConfig(request, env) {
  try {
    const { CF_API_TOKEN, CF_ZONE_ID } = env;

    if (!CF_API_TOKEN) {
      throw new Error('CF_API_TOKEN环境变量未设置');
    }

    if (!CF_ZONE_ID) {
      throw new Error('CF_ZONE_ID环境变量未设置');
    }

    const cleanZoneId = CF_ZONE_ID.trim();

    // 验证Zone ID格式
    if (!/^[a-f0-9]{32}$/.test(cleanZoneId)) {
      throw new Error('CF_ZONE_ID格式不正确，应为32位十六进制字符串');
    }

    // 测试API连接
    const zoneUrl = `https://api.cloudflare.com/client/v4/zones/${cleanZoneId}`;
    const response = await fetch(zoneUrl, {
      headers: {
        'Authorization': `Bearer ${CF_API_TOKEN}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Cloudflare API连接失败: ${response.status} ${error}`);
    }

    const data = await response.json();
    if (!data.success) {
      throw new Error(`Cloudflare API错误: ${data.errors?.[0]?.message || '未知错误'}`);
    }

    const zone = data.result;

    return new Response(JSON.stringify({
      success: true,
      message: 'Cloudflare配置验证成功',
      zone: {
        id: zone.id,
        name: zone.name,
        status: zone.status,
        plan: zone.plan?.name || '未知'
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Cloudflare配置验证失败:', error);
    return new Response(JSON.stringify({
      success: false,
      error: error.message
    }), {
      status: 400,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// 立即应用IP到DNS记录
async function applyIPsToDNS(request, env) {
  try {
    const { selectedIPs, targetDomains } = await request.json();

    if (!selectedIPs || selectedIPs.length === 0) {
      throw new Error('请选择要应用的IP地址');
    }

    if (!targetDomains || targetDomains.length === 0) {
      throw new Error('请选择要更新的域名');
    }

    console.log(`开始立即应用 ${selectedIPs.length} 个IP到 ${targetDomains.length} 个域名`);

    const updateResults = [];

    for (const domainName of targetDomains) {
      try {
        // 构造域名配置对象
        const domainConfig = {
          name: domainName,
          recordType: 'A',
          ttl: 300,
          maxIPs: selectedIPs.length
        };

        const result = await updateDNSRecords(env, domainConfig, selectedIPs);
        updateResults.push({
          domain: domainName,
          success: true,
          ips: result.ips,
          recordCount: result.records.length,
          message: `成功更新 ${result.records.length} 条DNS记录`
        });

        console.log(`域名 ${domainName} DNS记录更新成功，应用了 ${result.ips.length} 个IP`);
      } catch (error) {
        console.error(`域名 ${domainName} DNS记录更新失败:`, error);
        updateResults.push({
          domain: domainName,
          success: false,
          error: error.message,
          message: `更新失败: ${error.message}`
        });
      }
    }

    // 保存更新历史
    const history = {
      timestamp: new Date().toISOString(),
      type: 'manual_apply',
      optimalIPs: selectedIPs,
      updateResults,
      totalIPs: selectedIPs.length,
      successfulDomains: updateResults.filter(r => r.success).length,
      failedDomains: updateResults.filter(r => !r.success).length
    };

    await env.IP_STORE.put('last_update', JSON.stringify(history));

    const historyKey = `history_${Date.now()}`;
    await env.IP_STORE.put(historyKey, JSON.stringify(history));

    // 发送通知
    const successCount = history.successfulDomains;
    const failCount = history.failedDomains;

    await sendNotification(env, {
      type: successCount > 0 && failCount === 0 ? 'success' : failCount > 0 ? 'warning' : 'error',
      message: `手动应用IP完成：成功更新${successCount}个域名${failCount > 0 ? `，失败${failCount}个` : ''}`,
      details: history,
      timestamp: new Date().toISOString()
    });

    return new Response(JSON.stringify({
      success: true,
      message: `IP应用完成：成功更新${successCount}个域名${failCount > 0 ? `，失败${failCount}个` : ''}`,
      results: updateResults,
      summary: {
        totalDomains: targetDomains.length,
        successfulDomains: successCount,
        failedDomains: failCount,
        appliedIPs: selectedIPs.length
      }
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('立即应用IP失败:', error);
    return new Response(JSON.stringify({
      success: false,
      error: error.message
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
}

// 定时任务处理
async function handleScheduled(event, env, ctx) {
  console.log('开始执行定时任务：优选IP更新');

  try {
    const config = await env.IP_STORE.get('config');
    if (!config) {
      console.log('未找到配置信息，跳过执行');
      return;
    }

    const settings = JSON.parse(config);

    console.log('开始抓取优选IP...');
    const optimalIPs = await fetchOptimalIPs(settings.filters);

    if (optimalIPs.length === 0) {
      console.log('未找到符合条件的优选IP');
      await sendNotification(env, {
        type: 'warning',
        message: '未找到符合条件的优选IP',
        timestamp: new Date().toISOString()
      });
      return;
    }

    console.log(`找到 ${optimalIPs.length} 个符合条件的IP`);

    const updateResults = [];
    for (const domain of settings.domains || []) {
      try {
        const result = await updateDNSRecords(env, domain, optimalIPs);
        updateResults.push({
          domain: domain.name,
          success: true,
          ips: result.ips,
          recordId: result.recordId
        });
        console.log(`域名 ${domain.name} DNS记录更新成功`);
      } catch (error) {
        console.error(`域名 ${domain.name} DNS记录更新失败:`, error);
        updateResults.push({
          domain: domain.name,
          success: false,
          error: error.message
        });
      }
    }

    const history = {
      timestamp: new Date().toISOString(),
      optimalIPs,
      updateResults,
      totalIPs: optimalIPs.length,
      successfulDomains: updateResults.filter(r => r.success).length,
      failedDomains: updateResults.filter(r => !r.success).length
    };

    await env.IP_STORE.put('last_update', JSON.stringify(history));

    const historyKey = `history_${Date.now()}`;
    await env.IP_STORE.put(historyKey, JSON.stringify(history));

    await sendNotification(env, {
      type: 'success',
      message: `IP更新完成：找到${optimalIPs.length}个优选IP，成功更新${history.successfulDomains}个域名`,
      details: history,
      timestamp: new Date().toISOString()
    });

    console.log('定时任务执行完成');

  } catch (error) {
    console.error('定时任务执行失败:', error);

    await sendNotification(env, {
      type: 'error',
      message: `定时任务执行失败: ${error.message}`,
      timestamp: new Date().toISOString()
    });
  }
}

// 静态文件服务
async function handleStatic(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (path === '/' || path === '/index.html') {
    return new Response(getIndexHTML(), {
      headers: {
        ...corsHeaders,
        'Content-Type': 'text/html; charset=utf-8'
      }
    });
  }

  return new Response('Not Found', {
    status: 404,
    headers: corsHeaders
  });
}

function getIndexHTML() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP优化管理系统</title>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        .loading { animation: spin 1s linear infinite; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    </style>
</head>
<body class="bg-gray-100">
    <div id="root"></div>

    <script type="text/babel">
        const { useState, useEffect } = React;

        // API工具函数
        const api = {
            baseURL: window.location.origin,
            token: localStorage.getItem('token'),

            setToken(token) {
                this.token = token;
                localStorage.setItem('token', token);
            },

            clearToken() {
                this.token = null;
                localStorage.removeItem('token');
            },

            async request(endpoint, options = {}) {
                const url = \`\${this.baseURL}\${endpoint}\`;
                const config = {
                    headers: {
                        'Content-Type': 'application/json',
                        ...(this.token && { Authorization: \`Bearer \${this.token}\` })
                    },
                    ...options
                };

                if (config.body && typeof config.body === 'object') {
                    config.body = JSON.stringify(config.body);
                }

                const response = await fetch(url, config);
                const data = await response.json();

                if (!response.ok) {
                    throw new Error(data.error || '请求失败');
                }

                return data;
            }
        };

        // 登录组件
        function LoginForm({ onLogin }) {
            const [password, setPassword] = useState('');
            const [authCode, setAuthCode] = useState('');
            const [loading, setLoading] = useState(false);
            const [error, setError] = useState('');

            const handleSubmit = async (e) => {
                e.preventDefault();
                setLoading(true);
                setError('');

                try {
                    const result = await api.request('/api/auth/login', {
                        method: 'POST',
                        body: { password, authCode }
                    });

                    api.setToken(result.token);
                    onLogin(result.user);
                } catch (err) {
                    setError(err.message);
                } finally {
                    setLoading(false);
                }
            };

            return (
                <div className="min-h-screen flex items-center justify-center">
                    <div className="max-w-md w-full bg-white rounded-lg shadow-md p-6">
                        <h2 className="text-2xl font-bold text-center mb-6">IP优化管理系统</h2>
                        <form onSubmit={handleSubmit}>
                            <div className="mb-4">
                                <label className="block text-gray-700 text-sm font-bold mb-2">
                                    授权码
                                </label>
                                <input
                                    type="text"
                                    value={authCode}
                                    onChange={(e) => setAuthCode(e.target.value)}
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:border-blue-500"
                                    placeholder="请输入授权码"
                                    required
                                />
                            </div>
                            <div className="mb-4">
                                <label className="block text-gray-700 text-sm font-bold mb-2">
                                    管理员密码
                                </label>
                                <input
                                    type="password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:border-blue-500"
                                    placeholder="请输入管理员密码"
                                    required
                                />
                            </div>
                            {error && (
                                <div className="mb-4 text-red-600 text-sm">{error}</div>
                            )}
                            <button
                                type="submit"
                                disabled={loading}
                                className="w-full bg-blue-500 text-white py-2 px-4 rounded-md hover:bg-blue-600 disabled:opacity-50"
                            >
                                {loading ? '登录中...' : '登录'}
                            </button>
                        </form>
                        <div className="mt-4 text-sm text-gray-600">
                            <p>💡 使用说明：</p>
                            <ul className="list-disc list-inside mt-2 space-y-1">
                                <li>首先输入系统授权码（请联系管理员获取）</li>
                                <li>然后输入在环境变量中设置的管理员密码</li>
                                <li>登录后可以配置域名和通知设置</li>
                                <li>系统会每12小时自动更新IP</li>
                            </ul>
                        </div>
                    </div>
                </div>
            );
        }

        // 主应用组件
        function App() {
            const [user, setUser] = useState(null);
            const [loading, setLoading] = useState(true);

            useEffect(() => {
                checkAuth();
            }, []);

            const checkAuth = async () => {
                if (!api.token) {
                    setLoading(false);
                    return;
                }

                try {
                    // 简单验证：尝试获取状态
                    await api.request('/api/status');
                    setUser({ username: 'admin' });
                } catch (err) {
                    api.clearToken();
                } finally {
                    setLoading(false);
                }
            };

            const handleLogin = (userData) => {
                setUser(userData);
            };

            const handleLogout = () => {
                api.clearToken();
                setUser(null);
            };

            if (loading) {
                return (
                    <div className="min-h-screen flex items-center justify-center">
                        <div className="loading w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full"></div>
                    </div>
                );
            }

            if (!user) {
                return <LoginForm onLogin={handleLogin} />;
            }

            return <Dashboard user={user} onLogout={handleLogout} />;
        }

        // 仪表板组件
        function Dashboard({ user, onLogout }) {
            const [activeTab, setActiveTab] = useState('status');

            return (
                <div className="min-h-screen bg-gray-100">
                    <nav className="bg-white shadow-sm">
                        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                            <div className="flex justify-between h-16">
                                <div className="flex items-center">
                                    <h1 className="text-xl font-semibold">IP优化管理系统 (简化版)</h1>
                                </div>
                                <div className="flex items-center space-x-4">
                                    <span className="text-gray-700">欢迎，{user.username}</span>
                                    <button
                                        onClick={onLogout}
                                        className="text-red-600 hover:text-red-800"
                                    >
                                        退出登录
                                    </button>
                                </div>
                            </div>
                        </div>
                    </nav>

                    <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
                        <div className="px-4 py-6 sm:px-0">
                            <div className="border-b border-gray-200">
                                <nav className="-mb-px flex space-x-8">
                                    {[
                                        { id: 'status', name: '系统状态' },
                                        { id: 'config', name: '基础配置' },
                                        { id: 'domains', name: '域名管理' },
                                        { id: 'ips', name: '优选IP' }
                                    ].map((tab) => (
                                        <button
                                            key={tab.id}
                                            onClick={() => setActiveTab(tab.id)}
                                            className={\`py-2 px-1 border-b-2 font-medium text-sm \${
                                                activeTab === tab.id
                                                    ? 'border-blue-500 text-blue-600'
                                                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                                            }\`}
                                        >
                                            {tab.name}
                                        </button>
                                    ))}
                                </nav>
                            </div>

                            <div className="mt-6">
                                {activeTab === 'status' && <StatusPanel />}
                                {activeTab === 'config' && <ConfigPanel />}
                                {activeTab === 'domains' && <DomainsPanel />}
                                {activeTab === 'ips' && <IPsPanel />}
                            </div>
                        </div>
                    </div>
                </div>
            );
        }

        // 状态面板组件
        function StatusPanel() {
            const [status, setStatus] = useState(null);
            const [loading, setLoading] = useState(true);

            useEffect(() => {
                loadStatus();
            }, []);

            const loadStatus = async () => {
                try {
                    const result = await api.request('/api/status');
                    setStatus(result.status);
                } catch (err) {
                    console.error('加载状态失败:', err);
                } finally {
                    setLoading(false);
                }
            };

            if (loading) {
                return <div className="text-center">加载中...</div>;
            }

            return (
                <div className="bg-white shadow rounded-lg p-6">
                    <h3 className="text-lg font-medium mb-4">系统状态</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="border rounded-lg p-4">
                            <h4 className="font-medium text-gray-900">最后更新</h4>
                            <p className="text-sm text-gray-600">
                                {status?.lastUpdate ?
                                    new Date(status.lastUpdate.timestamp).toLocaleString('zh-CN') :
                                    '暂无数据'
                                }
                            </p>
                        </div>
                        <div className="border rounded-lg p-4">
                            <h4 className="font-medium text-gray-900">配置状态</h4>
                            <p className="text-sm text-gray-600">
                                {status?.configExists ? '已配置' : '未配置'}
                            </p>
                        </div>
                    </div>

                    {status?.lastUpdate && (
                        <div className="mt-6">
                            <h4 className="font-medium text-gray-900 mb-2">最新优选IP</h4>
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP地址</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">延迟</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">速度</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">位置</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {status.lastUpdate.optimalIPs?.slice(0, 5).map((ip, index) => (
                                            <tr key={index}>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900">{ip.ip}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{ip.latency}ms</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{ip.speed}kB/s</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{ip.location}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    <div className="mt-6 p-4 bg-blue-50 rounded-lg">
                        <h4 className="font-medium text-blue-900 mb-2">💡 简化版说明</h4>
                        <ul className="text-sm text-blue-800 space-y-1">
                            <li>• 这是预打包的简化版本，包含完整的管理功能</li>
                            <li>• 系统每12小时自动抓取优选IP并更新DNS</li>
                            <li>• 支持域名管理和A记录自动解析</li>
                            <li>• 可实时查看和获取优选IP数据</li>
                            <li>• 配置通过环境变量和Web界面管理</li>
                        </ul>
                    </div>
                </div>
            );
        }

        // 配置面板组件（简化版）
        function ConfigPanel() {
            const [config, setConfig] = useState(null);
            const [loading, setLoading] = useState(true);
            const [saving, setSaving] = useState(false);
            const [message, setMessage] = useState('');

            useEffect(() => {
                loadConfig();
            }, []);

            const loadConfig = async () => {
                try {
                    const result = await api.request('/api/config');
                    setConfig(result.config);
                } catch (err) {
                    console.error('加载配置失败:', err);
                    setMessage('加载配置失败: ' + err.message);
                } finally {
                    setLoading(false);
                }
            };

            const saveConfig = async () => {
                setSaving(true);
                setMessage('');

                try {
                    await api.request('/api/config', {
                        method: 'POST',
                        body: config
                    });
                    setMessage('配置保存成功！');
                } catch (err) {
                    setMessage('保存配置失败: ' + err.message);
                } finally {
                    setSaving(false);
                }
            };

            const testNotification = async () => {
                try {
                    await api.request('/api/notification/test', {
                        method: 'POST'
                    });
                    setMessage('测试通知发送成功！');
                } catch (err) {
                    setMessage('发送测试通知失败: ' + err.message);
                }
            };

            const verifyCloudflare = async () => {
                try {
                    const result = await api.request('/api/verify-cloudflare', {
                        method: 'POST'
                    });
                    if (result.success) {
                        setMessage(\`✅ Cloudflare配置验证成功！\\n域名: \${result.zone.name}\\n状态: \${result.zone.status}\\n套餐: \${result.zone.plan}\`);
                    } else {
                        setMessage(\`❌ Cloudflare配置验证失败: \${result.error}\`);
                    }
                } catch (err) {
                    setMessage(\`❌ Cloudflare配置验证失败: \${err.message}\`);
                }
            };

            if (loading) {
                return <div className="text-center">加载配置中...</div>;
            }

            if (!config) {
                return <div className="text-center text-red-600">配置加载失败</div>;
            }

            return (
                <div className="bg-white shadow rounded-lg p-6">
                    <h3 className="text-lg font-medium mb-6">基础配置</h3>

                    {message && (
                        <div className={\`mb-4 p-3 rounded \${message.includes('成功') ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}\`}>
                            {message}
                        </div>
                    )}

                    <div className="space-y-6">
                        {/* 息知通知配置 */}
                        <div>
                            <h4 className="text-md font-medium mb-3">息知通知设置</h4>
                            <div className="p-4 border rounded-lg">
                                <div className="flex items-center mb-2">
                                    <input
                                        type="checkbox"
                                        checked={config.notifications?.xizhi?.enabled || false}
                                        onChange={(e) => setConfig({
                                            ...config,
                                            notifications: {
                                                ...config.notifications,
                                                xizhi: { ...config.notifications?.xizhi, enabled: e.target.checked }
                                            }
                                        })}
                                        className="mr-2"
                                    />
                                    <label className="font-medium">启用息知通知</label>
                                </div>
                                {config.notifications?.xizhi?.enabled && (
                                    <div>
                                        <input
                                            type="text"
                                            placeholder="息知Key (从环境变量XIZHI_KEY获取)"
                                            value={config.notifications?.xizhi?.key || ''}
                                            onChange={(e) => setConfig({
                                                ...config,
                                                notifications: {
                                                    ...config.notifications,
                                                    xizhi: { ...config.notifications?.xizhi, key: e.target.value }
                                                }
                                            })}
                                            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:border-blue-500"
                                        />
                                        <p className="text-sm text-gray-500 mt-1">
                                            请访问 <a href="https://xizhi.qqoq.net" target="_blank" className="text-blue-500 hover:underline">https://xizhi.qqoq.net</a> 获取您的专属Key，
                                            然后在Cloudflare Workers环境变量中设置XIZHI_KEY
                                        </p>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Telegram通知配置 */}
                        <div>
                            <h4 className="text-md font-medium mb-3">Telegram机器人通知设置</h4>
                            <div className="p-4 border rounded-lg">
                                <div className="flex items-center mb-2">
                                    <input
                                        type="checkbox"
                                        checked={config.notifications?.telegram?.enabled || false}
                                        onChange={(e) => setConfig({
                                            ...config,
                                            notifications: {
                                                ...config.notifications,
                                                telegram: { ...config.notifications?.telegram, enabled: e.target.checked }
                                            }
                                        })}
                                        className="mr-2"
                                    />
                                    <label className="font-medium">启用Telegram通知</label>
                                </div>
                                {config.notifications?.telegram?.enabled && (
                                    <div className="space-y-3">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-1">Bot Token</label>
                                            <input
                                                type="text"
                                                placeholder="请输入Telegram Bot Token"
                                                value={config.notifications?.telegram?.botToken || ''}
                                                onChange={(e) => setConfig({
                                                    ...config,
                                                    notifications: {
                                                        ...config.notifications,
                                                        telegram: { ...config.notifications?.telegram, botToken: e.target.value }
                                                    }
                                                })}
                                                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:border-blue-500"
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 mb-1">Chat ID</label>
                                            <input
                                                type="text"
                                                placeholder="请输入Chat ID (个人或群组)"
                                                value={config.notifications?.telegram?.chatId || ''}
                                                onChange={(e) => setConfig({
                                                    ...config,
                                                    notifications: {
                                                        ...config.notifications,
                                                        telegram: { ...config.notifications?.telegram, chatId: e.target.value }
                                                    }
                                                })}
                                                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:border-blue-500"
                                            />
                                        </div>
                                        <div className="text-sm text-gray-500 space-y-1">
                                            <p><strong>📱 Telegram机器人设置步骤：</strong></p>
                                            <ol className="list-decimal list-inside space-y-1 ml-2">
                                                <li>与 <a href="https://t.me/BotFather" target="_blank" className="text-blue-500 hover:underline">@BotFather</a> 对话创建机器人</li>
                                                <li>发送 <code className="bg-gray-100 px-1 rounded">/newbot</code> 命令并按提示操作</li>
                                                <li>获取Bot Token并填入上方</li>
                                                <li>将机器人添加到群组或获取个人Chat ID</li>
                                                <li>获取Chat ID方法：发送消息给机器人后访问 <code className="bg-gray-100 px-1 rounded">https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates</code></li>
                                            </ol>
                                            <p className="mt-2">💡 <strong>提示：</strong>个人Chat ID通常是数字，群组Chat ID通常以负号开头</p>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* 域名配置说明 */}
                        <div>
                            <h4 className="text-md font-medium mb-3">域名配置说明</h4>
                            <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-lg">
                                <p className="text-sm text-yellow-800 mb-2">
                                    <strong>简化版域名配置：</strong>
                                </p>
                                <ul className="text-sm text-yellow-700 space-y-1">
                                    <li>• 域名配置需要通过修改代码中的配置对象</li>
                                    <li>• 或者通过API直接设置配置</li>
                                    <li>• 完整的域名管理功能请使用标准版本</li>
                                </ul>
                            </div>
                        </div>

                        {/* 操作按钮 */}
                        <div className="flex flex-wrap gap-4">
                            <button
                                onClick={saveConfig}
                                disabled={saving}
                                className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600 disabled:opacity-50"
                            >
                                {saving ? '保存中...' : '保存配置'}
                            </button>
                            <button
                                onClick={testNotification}
                                className="bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600"
                            >
                                测试通知
                            </button>
                            <button
                                onClick={verifyCloudflare}
                                className="bg-purple-500 text-white px-4 py-2 rounded-md hover:bg-purple-600"
                            >
                                验证Cloudflare配置
                            </button>
                        </div>
                    </div>
                </div>
            );
        }

        // 域名管理面板组件
        function DomainsPanel() {
            const [config, setConfig] = useState(null);
            const [loading, setLoading] = useState(true);
            const [saving, setSaving] = useState(false);
            const [message, setMessage] = useState('');
            const [newDomain, setNewDomain] = useState({
                name: '',
                recordType: 'A',
                ttl: 300,
                maxIPs: 3,
                comment: ''
            });

            useEffect(() => {
                loadConfig();
            }, []);

            const loadConfig = async () => {
                try {
                    const result = await api.request('/api/config');
                    setConfig(result.config);
                } catch (err) {
                    console.error('加载配置失败:', err);
                    setMessage('加载配置失败: ' + err.message);
                } finally {
                    setLoading(false);
                }
            };

            const addDomain = () => {
                if (!newDomain.name.trim()) {
                    setMessage('请输入域名');
                    return;
                }

                const updatedConfig = {
                    ...config,
                    domains: [...(config.domains || []), { ...newDomain }]
                };
                setConfig(updatedConfig);
                setNewDomain({
                    name: '',
                    recordType: 'A',
                    ttl: 300,
                    maxIPs: 3,
                    comment: ''
                });
                setMessage('域名已添加，请点击保存配置');
            };

            const removeDomain = (index) => {
                const updatedConfig = {
                    ...config,
                    domains: config.domains.filter((_, i) => i !== index)
                };
                setConfig(updatedConfig);
                setMessage('域名已删除，请点击保存配置');
            };

            const saveConfig = async () => {
                setSaving(true);
                setMessage('');

                try {
                    await api.request('/api/config', {
                        method: 'POST',
                        body: config
                    });
                    setMessage('配置保存成功！');
                } catch (err) {
                    setMessage('保存配置失败: ' + err.message);
                } finally {
                    setSaving(false);
                }
            };

            if (loading) {
                return <div className="text-center">加载中...</div>;
            }

            return (
                <div className="bg-white shadow rounded-lg p-6">
                    <h3 className="text-lg font-medium mb-4">域名管理</h3>

                    {message && (
                        <div className={\`mb-4 p-3 rounded-md \${message.includes('成功') ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}\`}>
                            {message}
                        </div>
                    )}

                    {/* 添加域名表单 */}
                    <div className="mb-6 p-4 border rounded-lg bg-gray-50">
                        <h4 className="text-md font-medium mb-3">添加新域名</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">域名</label>
                                <input
                                    type="text"
                                    value={newDomain.name}
                                    onChange={(e) => setNewDomain({...newDomain, name: e.target.value})}
                                    placeholder="example.com"
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">记录类型</label>
                                <select
                                    value={newDomain.recordType}
                                    onChange={(e) => setNewDomain({...newDomain, recordType: e.target.value})}
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                >
                                    <option value="A">A记录</option>
                                    <option value="AAAA">AAAA记录</option>
                                </select>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">TTL (秒)</label>
                                <input
                                    type="number"
                                    value={newDomain.ttl}
                                    onChange={(e) => setNewDomain({...newDomain, ttl: parseInt(e.target.value)})}
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">最大IP数</label>
                                <input
                                    type="number"
                                    value={newDomain.maxIPs}
                                    onChange={(e) => setNewDomain({...newDomain, maxIPs: parseInt(e.target.value)})}
                                    min="1"
                                    max="10"
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">备注</label>
                                <input
                                    type="text"
                                    value={newDomain.comment}
                                    onChange={(e) => setNewDomain({...newDomain, comment: e.target.value})}
                                    placeholder="可选"
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>
                            <div className="flex items-end">
                                <button
                                    onClick={addDomain}
                                    className="w-full bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600"
                                >
                                    添加域名
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* 域名列表 */}
                    <div className="mb-6">
                        <h4 className="text-md font-medium mb-3">已配置域名</h4>
                        {config.domains && config.domains.length > 0 ? (
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">域名</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">类型</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">TTL</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">最大IP数</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">备注</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {config.domains.map((domain, index) => (
                                            <tr key={index}>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{domain.name}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{domain.recordType}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{domain.ttl}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{domain.maxIPs}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{domain.comment || '-'}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                                    <button
                                                        onClick={() => removeDomain(index)}
                                                        className="text-red-600 hover:text-red-900"
                                                    >
                                                        删除
                                                    </button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                            <div className="text-center py-8 text-gray-500">
                                <p>暂无配置的域名</p>
                                <p className="text-sm mt-2">请添加需要进行A记录解析的域名</p>
                            </div>
                        )}
                    </div>

                    {/* 保存按钮 */}
                    <div className="flex justify-end">
                        <button
                            onClick={saveConfig}
                            disabled={saving}
                            className="bg-green-500 text-white px-6 py-2 rounded-md hover:bg-green-600 disabled:opacity-50"
                        >
                            {saving ? '保存中...' : '保存配置'}
                        </button>
                    </div>
                </div>
            );
        }

        // 优选IP面板组件
        function IPsPanel() {
            const [currentIPs, setCurrentIPs] = useState(null);
            const [availableIPs, setAvailableIPs] = useState(null);
            const [loading, setLoading] = useState(true);
            const [fetching, setFetching] = useState(false);
            const [applying, setApplying] = useState(false);
            const [message, setMessage] = useState('');
            const [selectedIPs, setSelectedIPs] = useState([]);
            const [showApplyModal, setShowApplyModal] = useState(false);
            const [domains, setDomains] = useState([]);
            const [selectedDomains, setSelectedDomains] = useState([]);
            const [filters, setFilters] = useState({
                minBandwidth: 10,
                minSpeed: 1000,
                maxLatency: 300,
                maxIPs: 10
            });
            const [savingFilters, setSavingFilters] = useState(false);

            useEffect(() => {
                loadCurrentIPs();
                loadDomains();
                loadFiltersFromConfig();
            }, []);

            const loadCurrentIPs = async () => {
                try {
                    const result = await api.request('/api/current-ips');
                    setCurrentIPs(result.data);
                } catch (err) {
                    console.error('加载当前IP失败:', err);
                } finally {
                    setLoading(false);
                }
            };

            const loadDomains = async () => {
                try {
                    const result = await api.request('/api/config');
                    if (result.success && result.config.domains) {
                        setDomains(result.config.domains);
                    }
                } catch (err) {
                    console.error('加载域名配置失败:', err);
                }
            };

            const loadFiltersFromConfig = async () => {
                try {
                    const result = await api.request('/api/config');
                    if (result.success && result.config.filters) {
                        setFilters(result.config.filters);
                    }
                } catch (err) {
                    console.error('加载筛选配置失败:', err);
                }
            };

            const saveFiltersToConfig = async () => {
                setSavingFilters(true);
                setMessage('');

                try {
                    // 先获取当前配置
                    const configResult = await api.request('/api/config');
                    const currentConfig = configResult.config;

                    // 更新筛选配置
                    const updatedConfig = {
                        ...currentConfig,
                        filters: filters
                    };

                    // 保存配置
                    await api.request('/api/config', {
                        method: 'POST',
                        body: updatedConfig
                    });

                    setMessage('✅ 筛选配置保存成功！');
                } catch (err) {
                    setMessage('❌ 保存筛选配置失败: ' + err.message);
                } finally {
                    setSavingFilters(false);
                }
            };

            const fetchAvailableIPs = async () => {
                setFetching(true);
                setMessage('');

                try {
                    const result = await api.request('/api/fetch-ips', {
                        method: 'POST',
                        body: { filters }
                    });
                    setAvailableIPs(result);
                    if (result.count > 0) {
                        // 检查是否使用了备用IP
                        const hasBackupIPs = result.ips.some(ip => ip.provider === 'Cloudflare');
                        if (hasBackupIPs && result.count <= 20) {
                            setMessage(\`✅ 成功获取 \${result.count} 个符合条件的优选IP\\n💡 注意：由于外部数据源访问限制，当前使用备用IP列表\`);
                        } else {
                            setMessage(\`✅ 成功获取 \${result.count} 个符合条件的优选IP\`);
                        }
                    } else {
                        setMessage('⚠️ 未找到符合条件的IP，请尝试放宽筛选条件');
                    }
                } catch (err) {
                    setMessage('获取优选IP失败: ' + err.message);
                } finally {
                    setFetching(false);
                }
            };

            const debugIPFetch = async () => {
                setFetching(true);
                setMessage('正在进行调试诊断...');

                try {
                    const result = await api.request('/api/debug-ips', {
                        method: 'POST',
                        body: { filters }
                    });

                    if (result.success) {
                        const debug = result.debug;
                        let debugMessage = '🔍 调试信息:\\n\\n';

                        debugMessage += '📋 执行步骤:\\n';
                        debug.steps.forEach((step, index) => {
                            debugMessage += \`\${index + 1}. \${step}\\n\`;
                        });

                        if (debug.errors.length > 0) {
                            debugMessage += '\\n❌ 错误信息:\\n';
                            debug.errors.forEach(error => {
                                debugMessage += \`• \${error}\\n\`;
                            });
                        }

                        if (debug.finalResult) {
                            debugMessage += \`\\n📊 最终结果:\\n\`;
                            debugMessage += \`• 总IP数: \${debug.finalResult.totalIPs}\\n\`;
                            debugMessage += \`• 符合条件: \${debug.finalResult.filteredIPs}\\n\`;
                            if (debug.finalResult.sampleIPs.length > 0) {
                                debugMessage += \`• 示例IP: \${debug.finalResult.sampleIPs[0].ip}\\n\`;
                            }
                        }

                        setMessage(debugMessage);
                    } else {
                        setMessage('调试失败: ' + result.error);
                    }
                } catch (err) {
                    setMessage('调试请求失败: ' + err.message);
                } finally {
                    setFetching(false);
                }
            };

            const handleIPSelection = (ip, isSelected) => {
                if (isSelected) {
                    setSelectedIPs(prev => [...prev, ip]);
                } else {
                    setSelectedIPs(prev => prev.filter(selectedIP => selectedIP.ip !== ip.ip));
                }
            };

            const handleSelectAllIPs = (isSelected) => {
                if (isSelected && availableIPs) {
                    setSelectedIPs([...availableIPs.ips]);
                } else {
                    setSelectedIPs([]);
                }
            };

            const handleDomainSelection = (domainName, isSelected) => {
                if (isSelected) {
                    setSelectedDomains(prev => [...prev, domainName]);
                } else {
                    setSelectedDomains(prev => prev.filter(name => name !== domainName));
                }
            };

            const handleApplyIPs = async () => {
                if (selectedIPs.length === 0) {
                    setMessage('请先选择要应用的IP地址');
                    return;
                }

                if (selectedDomains.length === 0) {
                    setMessage('请先选择要更新的域名');
                    return;
                }

                setApplying(true);
                setMessage('');

                try {
                    const result = await api.request('/api/apply-ips', {
                        method: 'POST',
                        body: {
                            selectedIPs: selectedIPs,
                            targetDomains: selectedDomains
                        }
                    });

                    if (result.success) {
                        setMessage(\`✅ \${result.message}\`);
                        setShowApplyModal(false);
                        setSelectedIPs([]);
                        setSelectedDomains([]);
                        // 重新加载当前IP数据
                        loadCurrentIPs();
                    } else {
                        setMessage(\`❌ 应用失败: \${result.error}\`);
                    }
                } catch (err) {
                    setMessage(\`❌ 应用失败: \${err.message}\`);
                } finally {
                    setApplying(false);
                }
            };

            const formatTimestamp = (timestamp) => {
                return new Date(timestamp).toLocaleString('zh-CN');
            };

            if (loading) {
                return <div className="text-center">加载中...</div>;
            }

            return (
                <div className="bg-white shadow rounded-lg p-6">
                    <h3 className="text-lg font-medium mb-4">优选IP管理</h3>

                    {message && (
                        <div className={\`mb-4 p-3 rounded-md \${message.includes('成功') ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}\`}>
                            {message}
                        </div>
                    )}

                    {/* 筛选条件 */}
                    <div className="mb-6 p-4 border rounded-lg bg-gray-50">
                        <h4 className="text-md font-medium mb-3">筛选条件
                            <span className="text-sm text-gray-500 font-normal ml-2">（可保存为默认配置）</span>
                        </h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">最小带宽 (Mbps)</label>
                                <input
                                    type="number"
                                    value={filters.minBandwidth}
                                    onChange={(e) => setFilters({...filters, minBandwidth: parseInt(e.target.value)})}
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">最小速度 (kB/s)</label>
                                <input
                                    type="number"
                                    value={filters.minSpeed}
                                    onChange={(e) => setFilters({...filters, minSpeed: parseInt(e.target.value)})}
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">最大延迟 (ms)</label>
                                <input
                                    type="number"
                                    value={filters.maxLatency}
                                    onChange={(e) => setFilters({...filters, maxLatency: parseInt(e.target.value)})}
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-gray-700 mb-1">最大IP数量</label>
                                <input
                                    type="number"
                                    value={filters.maxIPs}
                                    onChange={(e) => setFilters({...filters, maxIPs: parseInt(e.target.value)})}
                                    min="1"
                                    max="50"
                                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                />
                            </div>
                        </div>
                        <div className="mt-4 space-x-4">
                            <button
                                onClick={fetchAvailableIPs}
                                disabled={fetching}
                                className="bg-blue-500 text-white px-4 py-2 rounded-md hover:bg-blue-600 disabled:opacity-50"
                            >
                                {fetching ? '获取中...' : '获取可用IP'}
                            </button>
                            <button
                                onClick={saveFiltersToConfig}
                                disabled={savingFilters}
                                className="bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600 disabled:opacity-50"
                            >
                                {savingFilters ? '保存中...' : '保存筛选配置'}
                            </button>
                            <button
                                onClick={debugIPFetch}
                                disabled={fetching}
                                className="bg-yellow-500 text-white px-4 py-2 rounded-md hover:bg-yellow-600 disabled:opacity-50"
                            >
                                调试诊断
                            </button>
                        </div>
                    </div>

                    {/* 当前使用的IP */}
                    <div className="mb-6">
                        <h4 className="text-md font-medium mb-3">当前使用的优选IP</h4>
                        {currentIPs && currentIPs.optimalIPs ? (
                            <div>
                                <div className="mb-2 text-sm text-gray-600">
                                    最后更新时间: {formatTimestamp(currentIPs.timestamp)}
                                </div>
                                <div className="overflow-x-auto">
                                    <table className="min-w-full divide-y divide-gray-200">
                                        <thead className="bg-gray-50">
                                            <tr>
                                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP地址</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">延迟</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">速度</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">带宽</th>
                                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">位置</th>
                                            </tr>
                                        </thead>
                                        <tbody className="bg-white divide-y divide-gray-200">
                                            {currentIPs.optimalIPs.map((ip, index) => (
                                                <tr key={index}>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{ip.ip}</td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{ip.latency}ms</td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{ip.speed}kB/s</td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{ip.bandwidth}Mbps</td>
                                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{ip.location}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        ) : (
                            <div className="text-center py-8 text-gray-500">
                                <p>暂无当前使用的IP数据</p>
                                <p className="text-sm mt-2">系统尚未执行过IP优化任务</p>
                            </div>
                        )}
                    </div>

                    {/* 可用的优选IP */}
                    {availableIPs && (
                        <div className="mb-6">
                            <div className="flex justify-between items-center mb-3">
                                <h4 className="text-md font-medium">可用的优选IP</h4>
                                <div className="space-x-2">
                                    <button
                                        onClick={() => setShowApplyModal(true)}
                                        disabled={selectedIPs.length === 0}
                                        className="bg-green-500 text-white px-4 py-2 rounded-md hover:bg-green-600 disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        立即配置 ({selectedIPs.length})
                                    </button>
                                </div>
                            </div>
                            <div className="mb-2 text-sm text-gray-600">
                                获取时间: {formatTimestamp(availableIPs.timestamp)} | 共找到 {availableIPs.count} 个IP
                            </div>
                            <div className="overflow-x-auto">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-50">
                                        <tr>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                                <input
                                                    type="checkbox"
                                                    checked={selectedIPs.length === availableIPs.ips.length}
                                                    onChange={(e) => handleSelectAllIPs(e.target.checked)}
                                                    className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                                />
                                            </th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IP地址</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">延迟</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">速度</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">带宽</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">位置</th>
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">提供商</th>
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {availableIPs.ips.map((ip, index) => (
                                            <tr key={index} className={selectedIPs.some(selected => selected.ip === ip.ip) ? 'bg-blue-50' : ''}>
                                                <td className="px-6 py-4 whitespace-nowrap">
                                                    <input
                                                        type="checkbox"
                                                        checked={selectedIPs.some(selected => selected.ip === ip.ip)}
                                                        onChange={(e) => handleIPSelection(ip, e.target.checked)}
                                                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                                    />
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{ip.ip}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    <span className={\`px-2 py-1 text-xs rounded-full \${ip.latency <= 100 ? 'bg-green-100 text-green-800' : ip.latency <= 200 ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800'}\`}>
                                                        {ip.latency}ms
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{ip.speed}kB/s</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{ip.bandwidth}Mbps</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{ip.location}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{ip.provider}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* 立即配置模态框 */}
                    {showApplyModal && (
                        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
                            <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
                                <div className="mt-3">
                                    <h3 className="text-lg font-medium text-gray-900 mb-4">立即配置DNS记录</h3>

                                    <div className="mb-4">
                                        <h4 className="text-sm font-medium text-gray-700 mb-2">
                                            已选择的IP ({selectedIPs.length} 个):
                                        </h4>
                                        <div className="max-h-32 overflow-y-auto bg-gray-50 p-2 rounded border">
                                            {selectedIPs.map((ip, index) => (
                                                <div key={index} className="text-sm text-gray-600 mb-1">
                                                    {ip.ip} - {ip.latency}ms - {ip.location}
                                                </div>
                                            ))}
                                        </div>
                                    </div>

                                    <div className="mb-4">
                                        <h4 className="text-sm font-medium text-gray-700 mb-2">选择要更新的域名:</h4>
                                        {domains.length > 0 ? (
                                            <div className="space-y-2 max-h-32 overflow-y-auto">
                                                {domains.map((domain, index) => (
                                                    <label key={index} className="flex items-center">
                                                        <input
                                                            type="checkbox"
                                                            checked={selectedDomains.includes(domain.name)}
                                                            onChange={(e) => handleDomainSelection(domain.name, e.target.checked)}
                                                            className="rounded border-gray-300 text-blue-600 focus:ring-blue-500 mr-2"
                                                        />
                                                        <span className="text-sm text-gray-700">{domain.name}</span>
                                                    </label>
                                                ))}
                                            </div>
                                        ) : (
                                            <div className="text-sm text-gray-500 p-2 bg-yellow-50 rounded border">
                                                暂无配置的域名，请先在"域名管理"中添加域名配置
                                            </div>
                                        )}
                                    </div>

                                    <div className="flex justify-end space-x-3">
                                        <button
                                            onClick={() => setShowApplyModal(false)}
                                            className="px-4 py-2 bg-gray-300 text-gray-700 rounded-md hover:bg-gray-400"
                                        >
                                            取消
                                        </button>
                                        <button
                                            onClick={handleApplyIPs}
                                            disabled={applying || selectedDomains.length === 0}
                                            className="px-4 py-2 bg-green-500 text-white rounded-md hover:bg-green-600 disabled:opacity-50 disabled:cursor-not-allowed"
                                        >
                                            {applying ? '配置中...' : \`确认配置到 \${selectedDomains.length} 个域名\`}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
            );
        }

        // 渲染应用
        ReactDOM.render(<App />, document.getElementById('root'));
    </script>
</body>
</html>`;
}
