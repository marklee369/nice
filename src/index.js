import { Hono } from 'hono';
import { cors } from 'hono/cors';

const app = new Hono();

// CORS 中间件配置
// 注意：在生产环境中，应将 origin 设置为您的确切前端域名
app.use('/api/*', cors({
  origin: (origin) => {
    // 允许来自 localhost (不同端口) 和您指定的生产域名的请求
    const allowedOrigins = [
      'https://code.niceo.de',
      // 在这里添加您的生产环境前端域名
      // 例如: 'https://your-app-domain.com'
    ];
    if (allowedOrigins.includes(origin)) {
      return origin;
    }
    return null; // 其他来源将被拒绝
  },
  allowMethods: ['POST', 'GET', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'], // 如果未来需要认证头
  maxAge: 600, // 预检请求的缓存时间
}));


// 生成唯一ID
function generateId(length = 16) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

app.post('/api/create', async (c) => {
  try {
    const { encryptedPayload, expiryOption, readOnce } = await c.req.json();

    if (!encryptedPayload) {
      return c.json({ error: 'Encrypted payload is required' }, 400);
    }
    if (typeof encryptedPayload !== 'string' || encryptedPayload.length > 2000000) { // 限制大小，例如2MB
        return c.json({ error: 'Invalid payload or payload too large' }, 400);
    }


    const secretId = generateId();
    const creationTime = Date.now();
    let effectiveKvTtl; // KV条目的TTL (秒)

    if (readOnce) {
      // 对于阅后即焚，也设置一个服务器端TTL，比如1天，防止链接从未被访问
      effectiveKvTtl = 24 * 60 * 60; // 1 天
    } else {
      switch (expiryOption) {
        case '5min': effectiveKvTtl = 5 * 60; break;
        case '30min': effectiveKvTtl = 30 * 60; break;
        case '1hour': effectiveKvTtl = 60 * 60; break;
        case '6hour': effectiveKvTtl = 6 * 60 * 60; break;
        case '1day': effectiveKvTtl = 24 * 60 * 60; break;
        default: effectiveKvTtl = 24 * 60 * 60; // 默认1天
      }
    }

    // KV TTL 有最小值60秒的限制
    if (effectiveKvTtl < 60) {
        effectiveKvTtl = 60;
    }

    const metadata = { 
        readOnce, 
        creationTime, 
        userExpiryOption: expiryOption // 存储用户选择的过期选项，供前端参考
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
    if (!id || id.length > 32) { // 简单校验ID格式
        return c.json({ error: 'Invalid secret ID format' }, 400);
    }

    const { value, metadata } = await c.env.SECRETS_KV.getWithMetadata(id);

    if (!value) {
      return c.json({ error: 'Secret not found or expired' }, 404);
    }

    if (metadata?.readOnce) {
      c.executionCtx.waitUntil(c.env.SECRETS_KV.delete(id));
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
  // For non-API routes, you might serve a static HTML or let another handler manage it
  return c.text('Not Found', 404);
});


export default app;

