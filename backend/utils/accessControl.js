import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';

const SESSION_TTL_MS = 15 * 60 * 1000;
const MAX_ACTIVE_SESSIONS = 1000;
const MIN_SECRET_BYTES = 32;
const KNOWN_WEAK_SECRETS = new Set([
  'password',
  'changeme',
  'change-this',
  'replace-with-a-long-random-secret',
  'your-secret-here',
  'development-secret',
  'test-secret',
  Buffer.from('0123456789abcdef'.repeat(2)).toString('base64url')
]);

const digest = (value) => createHash('sha256').update(value).digest();
const OWNER_ID_PATTERN = /^[1-9]\d{0,19}$/;
const SESSION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const normalizeOwnerId = (ownerId) => {
  if (Number.isSafeInteger(ownerId) && ownerId > 0) {
    return String(ownerId);
  }
  if (typeof ownerId === 'string' && OWNER_ID_PATTERN.test(ownerId)) {
    return ownerId;
  }
  return null;
};

export const getAuthenticatedUserId = (req) => {
  const githubAuth = req?.session?.githubAuth;
  if (typeof githubAuth?.accessToken !== 'string' || githubAuth.accessToken.length === 0) {
    return null;
  }
  return normalizeOwnerId(githubAuth.id);
};

export const isValidConfiguredSecret = (value) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value) ||
      KNOWN_WEAK_SECRETS.has(value.toLowerCase())) {
    return false;
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length < MIN_SECRET_BYTES || bytes.toString('base64url') !== value) {
    return false;
  }
  const firstByte = bytes[0];
  const ascending = bytes.every((byte, index) => byte === (firstByte + index) % 256);
  const descending = bytes.every((byte, index) => byte === (firstByte - index + 256) % 256);
  const repeatedBytes = [1, 2, 4, 8, 16].some((blockSize) =>
    bytes.length > blockSize && bytes.length % blockSize === 0 &&
    bytes.subarray(blockSize).every((byte, index) => byte === bytes[index % blockSize])
  );
  const repeatedEncoding = [1, 2, 4, 8].some((blockSize) =>
    value.length > blockSize && value.length % blockSize === 0 &&
    [...value.slice(blockSize)].every((character, index) =>
      character === value[index % blockSize]
    )
  );
  return !ascending && !descending && !repeatedBytes && !repeatedEncoding;
};

const isLoopbackHostname = (hostname) => {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  const version = isIP(normalized);
  return normalized === 'localhost' ||
    (version === 4 && Number(normalized.split('.')[0]) === 127) ||
    (version === 6 && normalized === '::1');
};

const parseConfiguredUrl = (value, name, { originOnly = false, mustUseHttps = false } = {}) => {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`${name} must be an absolute URL`);
  }

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }

  if (!parsed.hostname || parsed.username || parsed.password || parsed.hash ||
      (originOnly && (parsed.pathname !== '/' || parsed.search))) {
    throw new Error(`${name} must not contain credentials, a path, query, or fragment`);
  }
  if (mustUseHttps && parsed.protocol !== 'https:') {
    throw new Error(`${name} must use HTTPS`);
  }
  if (!mustUseHttps && !['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`${name} must use HTTP or HTTPS`);
  }
  if (parsed.protocol === 'http:' && !isLoopbackHostname(parsed.hostname)) {
    throw new Error(`${name} may use HTTP only for a loopback hostname`);
  }

  return parsed;
};

export const resolveGithubUrlConfig = (env = process.env, {
  tlsProxyMode = env.LUMINICENT_TRUSTED_TLS_PROXY === 'true',
  localOnly = env.LUMINICENT_LOCAL_ONLY === 'true' ||
    env.LUMINICENT_COMPOSE_LOCAL_ONLY === 'true'
} = {}) => {
  const productionPublic = env.NODE_ENV === 'production' && !localOnly;
  const mustUseHttps = tlsProxyMode || productionPublic;
  const requiresExplicitUrls = mustUseHttps;
  const frontendValue = env.FRONTEND_URL ||
    (requiresExplicitUrls ? '' : 'http://localhost:5173');
  const callbackValue = env.GITHUB_CALLBACK_URL || env.GITHUB_REDIRECT_URI ||
    (requiresExplicitUrls ? '' : 'http://localhost:5000/api/github/callback');

  if (requiresExplicitUrls && (!env.FRONTEND_URL || !env.GITHUB_CALLBACK_URL)) {
    throw new Error('Production OAuth requires explicit FRONTEND_URL and GITHUB_CALLBACK_URL values');
  }

  const frontend = parseConfiguredUrl(frontendValue, 'FRONTEND_URL', {
    originOnly: true,
    mustUseHttps
  });
  const callback = parseConfiguredUrl(callbackValue, 'GITHUB_CALLBACK_URL', {
    mustUseHttps
  });
  if (!['/api/github/callback', '/auth/github/callback'].includes(callback.pathname) ||
      callback.search) {
    throw new Error('GITHUB_CALLBACK_URL must use the /api/github/callback or /auth/github/callback path without a query');
  }

  if (env.GITHUB_CALLBACK_URL && env.GITHUB_REDIRECT_URI) {
    const redirect = parseConfiguredUrl(env.GITHUB_REDIRECT_URI, 'GITHUB_REDIRECT_URI', {
      mustUseHttps
    });
    if (redirect.href !== callback.href) {
      throw new Error('GITHUB_REDIRECT_URI must match GITHUB_CALLBACK_URL');
    }
  }

  const configuredOrigins = env.CORS_ORIGIN === undefined
    ? (tlsProxyMode ? [] : ['http://localhost:5173', 'http://localhost:3000', 'http://localhost:5000'])
    : String(env.CORS_ORIGIN).split(',').map((origin) => origin.trim());
  if (configuredOrigins.length === 0 || configuredOrigins.some((origin) => !origin)) {
    throw new Error('CORS_ORIGIN must contain one or more exact origins');
  }
  const corsOrigins = configuredOrigins.map((origin) => {
    const parsed = parseConfiguredUrl(origin, 'CORS_ORIGIN', {
      originOnly: true,
      mustUseHttps
    });
    if (parsed.origin !== origin) {
      throw new Error('CORS_ORIGIN entries must be exact origins without a trailing slash');
    }
    return parsed.origin;
  });
  if (!corsOrigins.includes(frontend.origin)) {
    throw new Error('FRONTEND_URL origin must be included in CORS_ORIGIN');
  }

  return {
    frontendUrl: frontend.origin,
    callbackUrl: callback.href,
    corsOrigins
  };
};

export const configureProxyTrust = (app, securityConfig) => {
  app.set('trust proxy', securityConfig.tlsProxyMode ? '127.0.0.1' : false);
};

export const createSessionCookieOptions = (env, securityConfig) => ({
  httpOnly: true,
  secure: env.SESSION_SECURE === undefined
    ? securityConfig.tlsProxyMode || env.NODE_ENV === 'production'
    : env.SESSION_SECURE === 'true',
  sameSite: env.SESSION_SAME_SITE || (env.NODE_ENV === 'production' ? 'none' : 'lax'),
  maxAge: Number(env.SESSION_TTL_SECONDS || 86400) * 1000,
  path: '/',
  domain: env.COOKIE_DOMAIN || undefined
});

export const validateSecurityConfig = (env = process.env) => {
  const requestedHost = String(env.HOST || '127.0.0.1').trim();
  const normalizedHost = requestedHost.toLowerCase();
  const host = normalizedHost === 'localhost' ? '127.0.0.1' : requestedHost;
  const ipVersion = isIP(normalizedHost);
  const loopback = normalizedHost === 'localhost' ||
    (ipVersion === 4 && Number(normalizedHost.split('.')[0]) === 127) ||
    (ipVersion === 6 && normalizedHost === '::1');
  const readBoolean = (name) => {
    if (env[name] === undefined || env[name] === 'false') return false;
    if (env[name] === 'true') return true;
    throw new Error(`${name} must be "true" or "false"`);
  };
  const localOnly = readBoolean('LUMINICENT_LOCAL_ONLY');
  const composeLocalOnly = readBoolean('LUMINICENT_COMPOSE_LOCAL_ONLY');
  const tlsProxyMode = readBoolean('LUMINICENT_TRUSTED_TLS_PROXY');
  const sessionSecure = env.SESSION_SECURE === undefined
    ? env.NODE_ENV === 'production'
    : readBoolean('SESSION_SECURE');
  const sessionSameSite = env.SESSION_SAME_SITE ||
    (env.NODE_ENV === 'production' ? 'none' : 'lax');
  if (!['strict', 'lax', 'none'].includes(sessionSameSite)) {
    throw new Error('SESSION_SAME_SITE must be "strict", "lax", or "none"');
  }
  const executionMode = env.LUMINICENT_EXECUTION_MODE || 'disabled';
  const buildNetwork = env.LUMINICENT_BUILD_NETWORK || 'none';
  if (!['disabled', 'trusted-local'].includes(executionMode)) {
    throw new Error('LUMINICENT_EXECUTION_MODE must be "disabled" or "trusted-local"');
  }
  if (!['none', 'default'].includes(buildNetwork)) {
    throw new Error('LUMINICENT_BUILD_NETWORK must be "none" or "default"');
  }
  if (buildNetwork === 'default' && executionMode !== 'trusted-local') {
    throw new Error('LUMINICENT_BUILD_NETWORK=default requires trusted-local execution mode');
  }
  if (executionMode === 'trusted-local' &&
      (!localOnly || tlsProxyMode || (!loopback && !composeLocalOnly))) {
    throw new Error(
      'trusted-local execution requires an explicitly local-only loopback or Compose-local-only topology and cannot use trusted TLS proxy mode'
    );
  }
  if (!isValidConfiguredSecret(env.LUMINICENT_API_TOKEN)) {
    throw new Error(
      'LUMINICENT_API_TOKEN must be a canonical base64url value encoding at least 32 bytes; generate it with Node.js crypto.randomBytes(32)'
    );
  }
  if (!isValidConfiguredSecret(env.SESSION_SECRET)) {
    throw new Error(
      'SESSION_SECRET must be a canonical base64url value encoding at least 32 bytes; generate it with Node.js crypto.randomBytes(32)'
    );
  }
  if (env.LUMINICENT_API_TOKEN === env.SESSION_SECRET) {
    throw new Error('LUMINICENT_API_TOKEN and SESSION_SECRET must be different values');
  }
  if (tlsProxyMode) {
    if (host !== '127.0.0.1' || localOnly || composeLocalOnly ||
        env.NODE_ENV !== 'production' || env.SESSION_SECURE !== 'true' ||
        sessionSameSite !== env.SESSION_SAME_SITE) {
      throw new Error(
        'Trusted TLS proxy mode requires a 127.0.0.1 backend bind, production mode, explicitly secure cookies, and an explicit SESSION_SAME_SITE value'
      );
    }
  }
  if (sessionSameSite === 'none' && !sessionSecure) {
    throw new Error('SESSION_SAME_SITE=none requires SESSION_SECURE=true');
  }
  if (env.NODE_ENV === 'production' && !localOnly && !composeLocalOnly && !sessionSecure) {
    throw new Error('Non-local production deployments require SESSION_SECURE=true');
  }
  if (loopback && env.NODE_ENV === 'production' && !localOnly && !tlsProxyMode) {
    throw new Error(
      'Production loopback binding must explicitly select local-only mode or trusted TLS proxy mode'
    );
  }
  if (!loopback) {
    if (host !== '0.0.0.0' || !localOnly || !composeLocalOnly ||
        env.NODE_ENV !== 'production' || tlsProxyMode) {
      throw new Error(
        'Non-loopback binding is only supported for the local-only Docker Compose topology'
      );
    }
  }
  if (composeLocalOnly && (loopback || !localOnly || tlsProxyMode)) {
    throw new Error(
      'Compose local-only mode requires a wildcard container bind and LUMINICENT_LOCAL_ONLY=true'
    );
  }
  resolveGithubUrlConfig(env, { tlsProxyMode, localOnly: localOnly || composeLocalOnly });
  return { host, localOnly, composeLocalOnly, tlsProxyMode, executionMode, buildNetwork };
};

export const createApiTokenMiddleware = ({ getToken = () => process.env.LUMINICENT_API_TOKEN } = {}) =>
  (req, res, next) => {
    const expectedToken = getToken();
    const authorization = req.get('authorization') || '';
    const match = authorization.match(/^Bearer\s+(.+)$/i);
    if (!isValidConfiguredSecret(expectedToken) || !match ||
        !timingSafeEqual(digest(match[1]), digest(expectedToken))) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }
    next();
  };

export const createInMemorySessionRegistry = ({
  ttlMs = SESSION_TTL_MS,
  maxSessions = MAX_ACTIVE_SESSIONS,
  now = Date.now,
  sweepIntervalMs = 60 * 1000,
  onDelete = () => {}
} = {}) => {
  const sessions = new Map();
  const remove = (sessionId) => {
    if (!sessions.delete(sessionId)) return false;
    onDelete(sessionId);
    return true;
  };
  const sweep = () => {
    const time = now();
    for (const [sessionId, session] of sessions) {
      if (session.expiresAt <= time) remove(sessionId);
    }
  };
  const timer = setInterval(sweep, sweepIntervalMs);
  timer.unref?.();

  const verify = (sessionId, token, ownerId) => {
    sweep();
    const normalizedOwnerId = normalizeOwnerId(ownerId);
    if (typeof sessionId !== 'string' || !SESSION_ID_PATTERN.test(sessionId)
      || typeof token !== 'string' || !normalizedOwnerId) {
      return false;
    }
    const session = sessions.get(sessionId);
    return Boolean(session
      && session.ownerId === normalizedOwnerId
      && timingSafeEqual(session.tokenDigest, digest(token)));
  };

  return {
    create(ownerId) {
      sweep();
      const normalizedOwnerId = normalizeOwnerId(ownerId);
      if (!normalizedOwnerId) {
        throw new TypeError('An authenticated owner is required to create a session');
      }
      if (sessions.size >= maxSessions) {
        const error = new Error('Session capacity reached; retry after an active session expires or is cleaned up');
        error.code = 'SESSION_CAPACITY';
        throw error;
      }
      const sessionId = randomUUID();
      const sessionToken = randomBytes(32).toString('base64url');
      sessions.set(sessionId, {
        tokenDigest: digest(sessionToken),
        ownerId: normalizedOwnerId,
        expiresAt: now() + ttlMs
      });
      return { sessionId, sessionToken };
    },
    verify,
    delete(sessionId, token, ownerId) {
      if (!verify(sessionId, token, ownerId)) return false;
      return remove(sessionId);
    },
    has(sessionId, ownerId) {
      sweep();
      const session = sessions.get(sessionId);
      return Boolean(session && session.ownerId === normalizeOwnerId(ownerId));
    },
    getRemainingTtlMs(sessionId, ownerId) {
      sweep();
      const session = sessions.get(sessionId);
      return session?.ownerId === normalizeOwnerId(ownerId)
        ? Math.max(0, session.expiresAt - now())
        : null;
    },
    get size() {
      sweep();
      return sessions.size;
    },
    close() {
      clearInterval(timer);
      for (const sessionId of sessions.keys()) remove(sessionId);
    }
  };
};

export const registerSessionSocketHandlers = (io, sessionRegistry) => {
  io.on('connection', (socket) => {
    let expiryTimer;
    socket.on('joinSession', async (payload = {}, acknowledge = () => {}) => {
      const { sessionId, sessionToken } = payload;
      const ownerId = getAuthenticatedUserId(socket.request);
      let verified = false;
      let remainingTtlMs = null;
      try {
        verified = Boolean(ownerId &&
          await sessionRegistry.verify(sessionId, sessionToken, ownerId));
        if (verified && typeof sessionRegistry.getRemainingTtlMs === 'function') {
          remainingTtlMs = await sessionRegistry.getRemainingTtlMs(sessionId, ownerId);
          verified = Number.isSafeInteger(remainingTtlMs) && remainingTtlMs > 0;
        } else {
          verified = false;
        }
      } catch {
        acknowledge({ success: false, error: 'Session access denied' });
        return;
      }
      if (!verified) {
        acknowledge({ success: false, error: 'Session access denied' });
        return;
      }
      if (socket.data?.luminicentSessionId && socket.data.luminicentSessionId !== sessionId) {
        socket.leave(socket.data.luminicentSessionId);
      }
      clearTimeout(expiryTimer);
      if (socket.data) socket.data.luminicentSessionId = sessionId;
      socket.join(sessionId);
      if (Number.isSafeInteger(remainingTtlMs)) {
        expiryTimer = setTimeout(() => {
          if (socket.data?.luminicentSessionId === sessionId) {
            socket.leave(sessionId);
            delete socket.data.luminicentSessionId;
          }
        }, Math.max(0, remainingTtlMs));
        expiryTimer.unref?.();
      }
      acknowledge({ success: true });
    });
  });
};
