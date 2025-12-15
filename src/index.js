import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();

// ==================== 配置常量 ====================
const CONFIG = {
  MAX_PAYLOAD_SIZE: 10 * 1024 * 1024, // 10MB (注：Worker 免费版请求体限制 100MB，KV 单值上限 25MB)
  ID_LENGTH: 16,
  MAX_ID_LENGTH: 32,
  MIN_TTL: 60,
  DEFAULT_TTL: 24 * 60 * 60,
  READ_ONCE_TTL: 24 * 60 * 60,
  ALLOWED_ORIGINS: [
    'https://code.niceo.de',
  ],
  TTL_MAP: {
    '5min': 5 * 60,
    '30min': 30 * 60,
    '1hour': 60 * 60,
    '6hour': 6 * 60 * 60,
    '1day': 24 * 60 * 60,
  }
};

// ==================== 工具函数 ====================

/**
 * 生成请求指纹 (SHA-256 of IP + UA)
 */
async function getFingerprint(c) {
  const ip = c.req.header('CF-Connecting-IP') || '0.0.0.0';
  const ua = c.req.header('User-Agent') || 'unknown';
  const data = new TextEncoder().encode(`${ip}-${ua}`);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateId(length = CONFIG.ID_LENGTH) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  return Array.from(randomValues)
    .map((v) => characters[v % characters.length])
    .join('');
}

function validatePayload(encryptedPayload) {
  if (!encryptedPayload) return { valid: false, error: 'Encrypted payload is required' };
  if (typeof encryptedPayload !== 'string') return { valid: false, error: 'Invalid payload type' };
  if (encryptedPayload.length === 0) return { valid: false, error: 'Payload cannot be empty' };
  if (encryptedPayload.length > CONFIG.MAX_PAYLOAD_SIZE) return { valid: false, error: 'Payload too large' };
  return { valid: true };
}

function validateSecretId(id) {
  if (!id || typeof id !== 'string') return { valid: false, error: 'Invalid ID' };
  if (id.length > CONFIG.MAX_ID_LENGTH) return { valid: false, error: 'Invalid ID length' };
  if (!/^[A-Za-z0-9]+$/.test(id)) return { valid: false, error: 'Invalid ID format' };
  return { valid: true };
}

// ==================== 中间件 ====================

// CORS
app.use('/api/*', cors({
  origin: (origin) => CONFIG.ALLOWED_ORIGINS.includes(origin) ? origin : null,
  allowMethods: ['POST', 'GET', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600,
}));

// 速率限制中间件
app.use('/api/*', async (c, next) => {
  // 仅对变更操作或高频读取进行限制，OPTIONS 请求放行
  if (c.req.method === 'OPTIONS') return next();

  if (!c.env.LIMITER_SHORT || !c.env.LIMITER_OK) {
    console.error('Rate Limiter bindings missing');
    return c.json({ error: 'Server configuration error' }, 500);
  }

  try {
    const fingerprint = await getFingerprint(c);

    // 并行检查两个限制器以减少延迟
    const [shortLimit, longLimit] = await Promise.all([
      c.env.LIMITER_SHORT.limit({ key: fingerprint }),
      c.env.LIMITER_OK.limit({ key: fingerprint })
    ]);

    if (!shortLimit.success) {
      return c.json({ error: 'Too Many Requests (Rate limit exceeded: 30s)' }, 429);
    }

    if (!longLimit.success) {
      return c.json({ error: 'Too Many Requests (Rate limit exceeded: Daily)' }, 429);
    }

    await next();
  } catch (e) {
    console.error('Rate Limit Error:', e);
    // 降级策略：如果限流服务挂了，允许请求通过，或者返回 500，视业务重要性而定
    // 这里选择允许通过以保证可用性，或者你可以选择拦截
    await next(); 
  }
});

// ==================== API 路由 ====================

app.post('/api/create', async (c) => {
  try {
    // 严格的 JSON 解析错误处理
    let body;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: 'Invalid JSON' }, 400);
    }

    const { encryptedPayload, expiryOption, readOnce } = body;

    const validation = validatePayload(encryptedPayload);
    if (!validation.valid) return c.json({ error: validation.error }, 400);

    // ID 生成与冲突检测
    let secretId;
    let attempts = 0;
    while (attempts < 3) {
      secretId = generateId();
      // 使用 list 或 peek 检查可能比 get 更轻量，但 get 强一致性更好
      const existing = await c.env.SECRETS_KV.get(secretId); 
      if (!existing) break;
      attempts++;
    }

    if (attempts >= 3) {
      console.error('ID collision exhaust');
      return c.json({ error: 'Service busy, please try again' }, 503);
    }

    // 计算 TTL
    const effectiveKvTtl = Math.max(
      readOnce ? CONFIG.READ_ONCE_TTL : (CONFIG.TTL_MAP[expiryOption] || CONFIG.DEFAULT_TTL),
      CONFIG.MIN_TTL
    );

    const metadata = {
      readOnce: Boolean(readOnce),
      creationTime: Date.now(),
      userExpiryOption: expiryOption
    };

    await c.env.SECRETS_KV.put(secretId, encryptedPayload, {
      expirationTtl: effectiveKvTtl,
      metadata: metadata
    });

    return c.json({ secretId });

  } catch (e) {
    console.error('Create Error:', e);
    // 安全修复：不返回 e.message
    return c.json({ error: 'Failed to create secret' }, 500);
  }
});

app.get('/api/secret/:id', async (c) => {
  try {
    const { id } = c.req.param();
    
    const validation = validateSecretId(id);
    if (!validation.valid) return c.json({ error: validation.error }, 400);

    const result = await c.env.SECRETS_KV.getWithMetadata(id);

    if (!result || !result.value) {
      return c.json({ error: 'Secret not found or expired' }, 404);
    }

    const { value, metadata } = result;

    if (metadata?.readOnce) {
      // 关键：waitUntil 确保响应返回后继续执行删除，不阻塞用户
      c.executionCtx.waitUntil(
        c.env.SECRETS_KV.delete(id).catch(err => console.error('Delete Error:', err))
      );
    }

    return c.json({ encryptedPayload: value, metadata });

  } catch (e) {
    console.error('Retrieve Error:', e);
    return c.json({ error: 'Failed to retrieve secret' }, 500);
  }
});

// 404
app.notFound((c) => c.json({ error: 'Not Found' }, 404));

// 全局错误
app.onError((err, c) => {
  console.error('Global Error:', err);
  // 安全修复：隐藏内部错误详情
  return c.json({ error: 'Internal Server Error' }, 500);
});

export default app;
