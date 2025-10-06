import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();

// ==================== 配置常量 ====================
const CONFIG = {
  MAX_PAYLOAD_SIZE: 10 * 1024 * 1024, // 2MB
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

// ==================== CORS 中间件配置 ====================
app.use('/api/*', cors({
  origin: (origin) => {

    if (CONFIG.ALLOWED_ORIGINS.includes(origin)) {
      return origin;
    }
    
    return null;
  },
  allowMethods: ['POST', 'GET', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600,
}));

// ==================== 工具函数 ====================

/**
 * 生成唯一ID - 使用加密安全的随机数
 */
function generateId(length = CONFIG.ID_LENGTH) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const charactersLength = characters.length;
  let result = '';
  
  // 使用加密安全的随机数生成器
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  
  for (let i = 0; i < length; i++) {
    result += characters.charAt(randomValues[i] % charactersLength);
  }
  
  return result;
}

/**
 * 验证加密负载
 */
function validatePayload(encryptedPayload) {
  if (!encryptedPayload) {
    return { valid: false, error: 'Encrypted payload is required' };
  }
  
  if (typeof encryptedPayload !== 'string') {
    return { valid: false, error: 'Invalid payload type' };
  }
  
  if (encryptedPayload.length === 0) {
    return { valid: false, error: 'Payload cannot be empty' };
  }
  
  if (encryptedPayload.length > CONFIG.MAX_PAYLOAD_SIZE) {
    return { valid: false, error: 'Invalid payload or payload too large' };
  }
  
  return { valid: true };
}

/**
 * 验证 Secret ID
 */
function validateSecretId(id) {
  if (!id) {
    return { valid: false, error: 'Secret ID is required' };
  }
  
  if (typeof id !== 'string') {
    return { valid: false, error: 'Invalid secret ID type' };
  }
  
  if (id.length > CONFIG.MAX_ID_LENGTH) {
    return { valid: false, error: 'Invalid secret ID format' };
  }
  
  // 只允许字母数字字符
  if (!/^[A-Za-z0-9]+$/.test(id)) {
    return { valid: false, error: 'Invalid secret ID format' };
  }
  
  return { valid: true };
}

/**
 * 获取有效的 TTL
 */
function getEffectiveTTL(expiryOption, readOnce) {
  let effectiveKvTtl;
  
  if (readOnce) {
    effectiveKvTtl = CONFIG.READ_ONCE_TTL;
  } else {
    effectiveKvTtl = CONFIG.TTL_MAP[expiryOption] || CONFIG.DEFAULT_TTL;
  }
  
  // KV TTL 有最小值60秒的限制
  return Math.max(effectiveKvTtl, CONFIG.MIN_TTL);
}

// ==================== API 路由 ====================

app.post('/api/create', async (c) => {
  try {
    let body;
    try {
      body = await c.req.json();
    } catch (parseError) {
      return c.json({ error: 'Invalid JSON format' }, 400);
    }
    
    const { encryptedPayload, expiryOption, readOnce } = body;
    
    // 验证负载
    const validation = validatePayload(encryptedPayload);
    if (!validation.valid) {
      return c.json({ error: validation.error }, 400);
    }
    
    // 生成唯一ID（带冲突检测）
    let secretId;
    let attempts = 0;
    const maxAttempts = 3;
    
    do {
      secretId = generateId();
      const existing = await c.env.SECRETS_KV.get(secretId);
      if (!existing) break;
      attempts++;
    } while (attempts < maxAttempts);
    
    if (attempts >= maxAttempts) {
      console.error('Failed to generate unique ID after multiple attempts');
      return c.json({ error: 'Failed to create secret' }, 500);
    }
    
    const creationTime = Date.now();
    const effectiveKvTtl = getEffectiveTTL(expiryOption, readOnce);
    
    const metadata = { 
      readOnce: Boolean(readOnce), 
      creationTime, 
      userExpiryOption: expiryOption
    };
    
    await c.env.SECRETS_KV.put(secretId, encryptedPayload, {
      expirationTtl: effectiveKvTtl,
      metadata: metadata
    });
    
    return c.json({ secretId });
    
  } catch (e) {
    console.error('Error creating secret:', e);
    return c.json({ error: 'Failed to create secret', details: e.message }, 500);
  }
});

app.get('/api/secret/:id', async (c) => {
  try {
    const { id } = c.req.param();
    
    // 验证ID格式
    const validation = validateSecretId(id);
    if (!validation.valid) {
      return c.json({ error: validation.error }, 400);
    }
    
    const result = await c.env.SECRETS_KV.getWithMetadata(id);
    
    if (!result || !result.value) {
      return c.json({ error: 'Secret not found or expired' }, 404);
    }
    
    const { value, metadata } = result;
    
    // 如果是阅后即焚，异步删除
    if (metadata?.readOnce) {
      c.executionCtx.waitUntil(
        c.env.SECRETS_KV.delete(id).catch(err => {
          console.error(`Failed to delete read-once secret ${id}:`, err);
        })
      );
    }
    
    return c.json({ encryptedPayload: value, metadata });
    
  } catch (e) {
    console.error('Error retrieving secret:', e);
    return c.json({ error: 'Failed to retrieve secret', details: e.message }, 500);
  }
});

// 404 Handler for API routes
app.notFound((c) => {
  if (c.req.path.startsWith('/api/')) {
    return c.json({ error: 'API endpoint not found' }, 404);
  }
  return c.text('Not Found', 404);
});

// 全局错误处理
app.onError((err, c) => {
  console.error('Unhandled error:', err);
  return c.json({ error: 'Internal server error', details: err.message }, 500);
});

export default app;
