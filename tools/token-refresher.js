/**
 * Kiro Token 自动刷新服务（改进版）
 *
 * 从 eskysoft 服务器获取凭证后：
 *   1. 通过 kiro-rs Admin API 热注入（立即生效，无需重启）
 *   2. Admin API 内部会自动持久化到 credentials.json
 *
 * 环境变量：
 *   KIRO_LICENSE_CODE       - 必填，license code
 *   KIRO_SERVER_URL         - 可选，eskysoft 服务地址，默认 http://kiro.eskysoft.com:9123
 *   KIRO_DEVICE_ID          - 可选，设备ID（容器内建议手动指定）
 *   KIRO_DEVICE_ID_FILE     - 可选，设备ID文件路径，默认 ~/.kiro-device-id
 *   KIRO_REASSIGN           - 可选，设为 1 启用强制抢占
 *   KIRO_REFRESH_INTERVAL   - 可选，刷新间隔（毫秒），默认 900000（15分钟）
 *   KIRO_HEARTBEAT_INTERVAL - 可选，heartbeat 间隔（毫秒），默认 60000（1分钟）
 *   KIRO_CLAIM_INTERVAL     - 可选，claim-active 间隔（毫秒），默认 300000（5分钟）
 *   KIRO_CLIENT_VERSION     - 可选，客户端版本，默认 1.1.2
 *   KIRO_RS_URL             - 可选，kiro-rs 地址，默认 http://127.0.0.1:8990
 *   KIRO_ADMIN_API_KEY      - 可选，Admin API Key，默认从 config.json 读取
 *   KIRO_CONFIG_DIR         - 可选，配置目录，默认 /app/config
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const os = require('os');
const fs = require('fs');
const path = require('path');

// ============ 配置 ============
const SERVER_URL = process.env.KIRO_SERVER_URL || 'http://kiro.eskysoft.com:9123';
const REFRESH_INTERVAL = Number.parseInt(process.env.KIRO_REFRESH_INTERVAL, 10) || 15 * 60 * 1000;
const HEARTBEAT_INTERVAL = Math.max(
  5000,
  Number.parseInt(process.env.KIRO_HEARTBEAT_INTERVAL, 10) || 60 * 1000
);
const CLAIM_ACTIVE_INTERVAL = Math.max(
  HEARTBEAT_INTERVAL,
  Number.parseInt(process.env.KIRO_CLAIM_INTERVAL, 10) || 5 * 60 * 1000
);
const CLIENT_VERSION = process.env.KIRO_CLIENT_VERSION || '1.1.2';
const CONFIG_DIR = process.env.KIRO_CONFIG_DIR || '/app/config';
const CONFIG_PATH = path.join(CONFIG_DIR, 'config.json');

// kiro-rs Admin API 配置
const KIRO_RS_URL = process.env.KIRO_RS_URL || 'http://127.0.0.1:8990';

// 固定 deviceId（容器内网卡/hostname 与宿主机不同，必须手动指定）
const FIXED_DEVICE_ID = process.env.KIRO_DEVICE_ID || '';
const DEVICE_ID_FILE = process.env.KIRO_DEVICE_ID_FILE || path.join(os.homedir(), '.kiro-device-id');

// ============ 工具函数 ============

function log(...args) {
  console.log('[refresher]', new Date().toISOString(), ...args);
}

function getAdminApiKey() {
  // 优先环境变量
  if (process.env.KIRO_ADMIN_API_KEY) return process.env.KIRO_ADMIN_API_KEY;
  // 从 config.json 读取（只取 adminApiKey，不回退 apiKey）
  try {
    const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
    return config.adminApiKey || '';
  } catch (e) {
    return '';
  }
}

function getDeviceId() {
  if (FIXED_DEVICE_ID) return FIXED_DEVICE_ID;

  try {
    const existing = fs.readFileSync(DEVICE_ID_FILE, 'utf-8').trim();
    if (/^[a-fA-F0-9]{32}$/.test(existing)) {
      return existing.toLowerCase();
    }
  } catch (e) {
    // 文件不存在时自动生成
  }

  const generated = crypto.randomBytes(16).toString('hex');
  try {
    fs.mkdirSync(path.dirname(DEVICE_ID_FILE), { recursive: true });
    fs.writeFileSync(DEVICE_ID_FILE, `${generated}\n`, { encoding: 'utf-8', mode: 0o600 });
  } catch (e) {
    log('写入 deviceId 文件失败:', e.message);
  }
  return generated;
}

function extractRegionFromArn(profileArn) {
  if (!profileArn) return '';
  const parts = profileArn.split(':');
  return parts.length >= 4 ? parts[3] : '';
}

// ============ HTTP 请求 ============

function serverRequest(serverUrl, apiPath, body) {
  return new Promise((resolve, reject) => {
    let url = serverUrl;
    if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
    let parsed;
    try { parsed = new URL(url); } catch (e) { return reject(new Error('服务器地址格式错误')); }

    const data = JSON.stringify(body);
    const isHttps = parsed.protocol === 'https:';
    const mod = isHttps ? https : http;

    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: apiPath,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
      },
      timeout: 10000,
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString()));
        } catch (e) {
          reject(new Error('响应解析失败'));
        }
      });
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('请求超时 (10s)')); });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

/**
 * 调用 kiro-rs Admin API（简单 HTTP 请求）
 */
function adminApiRequest(method, apiPath, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(KIRO_RS_URL);
    const data = body ? JSON.stringify(body) : '';
    const isHttps = parsed.protocol === 'https:';
    const mod = isHttps ? https : http;
    const apiKey = getAdminApiKey();

    const headers = {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
    };
    if (data) headers['Content-Length'] = Buffer.byteLength(data);

    const req = mod.request({
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: '/api/admin' + apiPath,
      method: method,
      headers: headers,
      timeout: 30000,  // Admin API 的 add_credential 会做 token 刷新验证，需要更久
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try {
          const result = JSON.parse(Buffer.concat(chunks).toString());
          resolve({ statusCode: res.statusCode, data: result });
        } catch (e) {
          resolve({ statusCode: res.statusCode, data: Buffer.concat(chunks).toString() });
        }
      });
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('Admin API 请求超时 (30s)')); });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ============ 解密 ============

const RSA_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzSEy6tgft6momfTbXV54
H1gTUgIqkjA103aQwyiolpdXmPY1NoCVR4IzgkZppoXNyYGtfJP1bbxYJHR3l0kX
ksnUe0Y8iuV75bjvHYMgOdNR1iqqRlQ8DM7FAq0IJ1Y5sY8UN8zqzkI9tGUrDaCh
0aIl7dXpKbhfBw4EbIGzsjTmSlbK1i25Jcq55knvKZVlH4E9N+zqETUIY5Njd3Xd
bVz53eaxXu1etKCf8VoFZWp7J3/0WR4CvThsZRtjls0YGTpZCuFwSg9byWwF0VKv
Mvr1L6n3eCH7UdEnLCJ2w9VSaGQ+lfcLBt5LTAhZzZrGikvyrllYmbUX9Ts3UzyQ
GQIDAQAB
-----END PUBLIC KEY-----`;

function decryptResponse(data) {
  if (!data || !data.encrypted) return data;
  const encKey = Buffer.from(data.key, 'base64');
  const iv = Buffer.from(data.iv, 'base64');
  const tag = Buffer.from(data.tag, 'base64');
  const enc = Buffer.from(data.data, 'base64');

  const aesKey = crypto.publicDecrypt({
    key: RSA_PUBLIC_KEY,
    padding: crypto.constants.RSA_PKCS1_PADDING,
  }, encKey);

  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
  decipher.setAuthTag(tag);
  const result = Buffer.concat([decipher.update(enc), decipher.final()]);
  return JSON.parse(result.toString('utf8'));
}

function decodeServerResponse(resp, apiPath) {
  let result = resp;
  if (resp && resp.encrypted) {
    try {
      result = decryptResponse(resp);
    } catch (e) {
      throw new Error(`${apiPath} 解密失败: ${e.message}`);
    }
  }

  if (!result || !result.success) {
    throw new Error(result?.message || `${apiPath} 请求失败`);
  }

  return result;
}

async function callLicenseApi(apiPath, body) {
  const resp = await serverRequest(SERVER_URL, apiPath, body);
  return decodeServerResponse(resp, apiPath);
}

// ============ 核心逻辑 ============

/**
 * 从 eskysoft 服务器获取凭证
 */
async function fetchCredentials(licenseCode, reassign = false) {
  const deviceId = getDeviceId();
  log('deviceId:', deviceId);

  const body = {
    code: licenseCode,
    deviceId: deviceId,
    clientVersion: CLIENT_VERSION,
  };
  if (reassign) body.reassign = true;

  const result = await callLicenseApi('/api/get-credentials', body);

  const data = result.data || result;
  const mergedCredentials = (data.credentials && typeof data.credentials === 'object')
    ? { ...data.credentials }
    : {};

  const fields = [
    'accessToken',
    'refreshToken',
    'clientId',
    'clientSecret',
    'expiresAt',
    'region',
    'profileArn',
    'authMethod',
    'machineId',
  ];
  for (const field of fields) {
    if (data[field] !== undefined && data[field] !== null && data[field] !== '') {
      mergedCredentials[field] = data[field];
    }
  }

  if (!mergedCredentials.refreshToken) {
    throw new Error('服务端返回缺少 refreshToken');
  }

  log('license 有效至:', data.licenseExpiresAt || result.licenseExpiresAt || '未知');
  if (data.kicked === true) {
    log('⚠️ 服务端返回 kicked=true，账号可能被其他设备抢占');
  }
  return mergedCredentials;
}

async function claimActive(licenseCode) {
  const body = {
    code: licenseCode,
    deviceId: getDeviceId(),
  };
  await callLicenseApi('/api/claim-active', body);
}

async function heartbeat(licenseCode) {
  const body = {
    code: licenseCode,
    deviceId: getDeviceId(),
  };
  await callLicenseApi('/api/heartbeat', body);
}

/**
 * 通过 Admin API 热注入凭证到 kiro-rs
 *
 * Admin API 内部会：
 *   1. 验证 refreshToken 有效性（调 AWS OIDC 刷新）
 *   2. 自动分配 ID
 *   3. 注入内存（立即生效）
 *   4. 持久化到 credentials.json
 *   5. 查询 subscriptionTitle
 */
async function injectViaAdminApi(creds) {
  // 无 adminApiKey 时直接跳过，避免无效 401 请求
  const apiKey = getAdminApiKey();
  if (!apiKey) {
    log('⚠️ 未配置 adminApiKey，跳过 Admin API 热注入');
    return { success: false, error: 'no adminApiKey' };
  }

  const region = extractRegionFromArn(creds.profileArn) || creds.region || 'us-east-1';
  const authMethod = creds.authMethod || 'idc';

  const body = {
    refreshToken: creds.refreshToken,
    authMethod: authMethod,
    clientId: creds.clientId || undefined,
    clientSecret: creds.clientSecret || undefined,
    region: region,
    machineId: creds.machineId || undefined,
  };

  log('调用 Admin API 热注入...');
  const resp = await adminApiRequest('POST', '/credentials', body);

  if (resp.statusCode >= 200 && resp.statusCode < 300) {
    log('✅ 热注入成功:', JSON.stringify(resp.data));
    return { success: true, data: resp.data };
  }

  // 处理常见错误
  const errMsg = resp.data?.error?.message || JSON.stringify(resp.data);

  if (resp.statusCode === 400 && errMsg.includes('重复')) {
    // refreshToken 重复 = 凭证没变，不需要注入
    log('⚠️ 凭证未变化（refreshToken 重复），跳过');
    return { success: true, skipped: true };
  }

  if (resp.statusCode === 401) {
    log('❌ Admin API 认证失败，请检查 adminApiKey');
    return { success: false, error: 'Admin API 认证失败' };
  }

  log('❌ 热注入失败:', resp.statusCode, errMsg);
  return { success: false, error: errMsg };
}

/**
 * 回退方案：直接写入 credentials.json（Admin API 不可用时）
 */
function fallbackWriteCredentials(creds) {
  if (!creds || !creds.refreshToken) {
    throw new Error('fallback 写入失败：凭证缺少 refreshToken');
  }

  let machineId = '';
  try {
    const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
    machineId = config.machineId || '';
  } catch (e) {}

  if (!machineId) {
    const nets = os.networkInterfaces();
    let mac = '';
    for (const name of Object.keys(nets)) {
      for (const net of nets[name]) {
        if (!net.internal && net.mac && net.mac !== '00:00:00:00:00:00') {
          mac = net.mac; break;
        }
      }
      if (mac) break;
    }
    machineId = crypto.createHash('sha256').update(
      os.hostname() + '-' + os.platform() + '-' + (mac || 'no-mac')
    ).digest('hex');
  }

  const credPath = process.env.KIRO_CREDENTIALS_PATH || path.join(CONFIG_DIR, 'credentials.json');
  let existing = [];
  try {
    const raw = JSON.parse(fs.readFileSync(credPath, 'utf-8'));
    if (Array.isArray(raw)) {
      existing = raw;
    } else if (raw && typeof raw === 'object') {
      // 兼容旧的单对象格式，转为数组保留原有凭证
      log('(fallback) 检测到单对象格式凭证，自动转换为数组格式');
      existing = [raw];
    }
  } catch (e) {
    // 文件不存在或解析失败，备份后用空数组
    try {
      if (fs.existsSync(credPath)) {
        const backupPath = credPath + '.bak.' + Date.now();
        fs.copyFileSync(credPath, backupPath);
        log('(fallback) 已备份损坏的凭证文件到', backupPath);
      }
    } catch (_) {}
  }

  const region = extractRegionFromArn(creds.profileArn) || creds.region || 'us-east-1';

  const entry = {
    accessToken: creds.accessToken,
    refreshToken: creds.refreshToken,
    expiresAt: creds.expiresAt || new Date(Date.now() + 3600000).toISOString(),
    authMethod: 'idc',
    clientId: creds.clientId || '',
    clientSecret: creds.clientSecret || '',
    profileArn: creds.profileArn || '',
    region: region,
    machineId: machineId,
    disabled: false,
  };

  // 按 refreshToken 哈希判断是否已存在
  const newHash = crypto.createHash('sha256').update(creds.refreshToken).digest('hex');
  const idx = existing.findIndex(e =>
    e.refreshToken && crypto.createHash('sha256').update(e.refreshToken).digest('hex') === newHash
  );

  if (idx >= 0) {
    entry.id = existing[idx].id;
    if (existing[idx].priority !== undefined) entry.priority = existing[idx].priority;
    if (existing[idx].subscriptionTitle) entry.subscriptionTitle = existing[idx].subscriptionTitle;
    existing[idx] = entry;
    log('(fallback) 更新条目 id:', entry.id);
  } else {
    const maxId = existing.reduce((m, e) => Math.max(m, e.id || 0), 0);
    entry.id = maxId + 1;
    existing.push(entry);
    log('(fallback) 新增条目 id:', entry.id);
  }

  const tmpPath = `${credPath}.tmp.${process.pid}.${Date.now()}`;
  fs.writeFileSync(tmpPath, JSON.stringify(existing, null, 2), 'utf-8');
  fs.renameSync(tmpPath, credPath);
  log('(fallback) 写入', credPath, '（需重启 kiro-rs 生效）');
}

// ============ 主流程 ============

async function refresh(licenseCode, reassign) {
  log('--- 开始刷新 ---');

  // Step 1: 从 eskysoft 获取凭证
  const creds = await fetchCredentials(licenseCode, reassign);

  // Step 2: 优先走 Admin API 热注入
  try {
    const result = await injectViaAdminApi(creds);
    if (result.success) return;
  } catch (e) {
    log('Admin API 不可用:', e.message);
  }

  // Step 3: 回退：直接写文件（kiro-rs 可能还没启动）
  log('回退到文件写入模式...');
  fallbackWriteCredentials(creds);
}

let refreshInFlight = false;
let keepAliveInFlight = false;
let lastClaimActiveAt = 0;

async function main() {
  const licenseCode = process.env.KIRO_LICENSE_CODE;
  const reassign = process.env.KIRO_REASSIGN === '1';

  if (!licenseCode) {
    log('错误: 未设置 KIRO_LICENSE_CODE 环境变量');
    log('刷新服务未启动，kiro-rs 将使用现有凭证');
    return;
  }

  log('=== Token 自动刷新服务启动 ===');
  log('刷新间隔:', REFRESH_INTERVAL / 1000 / 60, '分钟');
  log('heartbeat 间隔:', HEARTBEAT_INTERVAL / 1000, '秒');
  log('claim-active 间隔:', CLAIM_ACTIVE_INTERVAL / 1000, '秒');
  log('eskysoft 服务器:', SERVER_URL);
  log('kiro-rs 地址:', KIRO_RS_URL);
  log('Admin API Key:', getAdminApiKey() ? '已配置' : '未配置');
  log('deviceId 文件:', DEVICE_ID_FILE);

  async function scheduleRefresh() {
    if (refreshInFlight) {
      log('上一次刷新仍在进行，跳过本轮');
      setTimeout(scheduleRefresh, REFRESH_INTERVAL);
      return;
    }
    refreshInFlight = true;
    try {
      await refresh(licenseCode, reassign);
    } catch (e) {
      log('刷新失败:', e.message);
    } finally {
      refreshInFlight = false;
    }
    // 本次结束后再排下一次，避免重叠
    setTimeout(scheduleRefresh, REFRESH_INTERVAL);
  }

  async function scheduleKeepAlive() {
    if (keepAliveInFlight) {
      setTimeout(scheduleKeepAlive, HEARTBEAT_INTERVAL);
      return;
    }

    keepAliveInFlight = true;
    try {
      const now = Date.now();
      if (now - lastClaimActiveAt >= CLAIM_ACTIVE_INTERVAL) {
        await claimActive(licenseCode);
        lastClaimActiveAt = now;
        log('claim-active 成功');
      }

      await heartbeat(licenseCode);
    } catch (e) {
      log('保活失败:', e.message);
    } finally {
      keepAliveInFlight = false;
    }

    setTimeout(scheduleKeepAlive, HEARTBEAT_INTERVAL);
  }

  // 启动后等 5 秒再第一次刷新（让 kiro-rs 先启动）
  setTimeout(scheduleRefresh, 5000);
  // 启动后等 10 秒开始保活
  setTimeout(scheduleKeepAlive, 10000);
}

main();
