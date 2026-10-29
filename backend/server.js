import dotenv from "dotenv";
import cors from "cors";
import express from "express";
import http from "http";
import session from "express-session";
import { RedisStore } from "connect-redis";
import { createClient } from "redis";
import { Server as socketIO } from "socket.io";
import DockerOrchestrator from "./utils/dockerOrchestrator.js";
import uploadRoutes from "./routes/upload.js";
import githubRoutes from "./routes/githubRoutes.js";
import passport from "passport";
import {
  configureProxyTrust,
  createSessionCookieOptions,
  registerSessionSocketHandlers,
  resolveGithubUrlConfig,
  validateSecurityConfig
} from "./utils/accessControl.js";
import {
  createRedisScanRecordStore,
  createRedisSessionRegistry,
  validateRedisConfiguration
} from "./utils/redisPersistence.js";

// Load environment variables
dotenv.config();

const securityConfig = validateSecurityConfig();
const app = express();
const { corsOrigins: allowedOrigins } = resolveGithubUrlConfig(process.env, securityConfig);
const sessionCookieName =
  process.env.SESSION_COOKIE_NAME || "luminicent_session";
const sessionSecret = process.env.SESSION_SECRET;

const checkOrigin = (origin, callback) => {
  if (!origin) return callback(null, true);
  if (allowedOrigins.includes(origin)) return callback(null, true);
  return callback(new Error("Not allowed by CORS"));
};

let redisClient;
let sessionStore;
const initializeSessionStore = async () => {
  const redisUrl = validateRedisConfiguration(process.env);
  let initializing = true;
  redisClient = createClient({
    url: redisUrl,
    socket: {
      connectTimeout: 5000,
      reconnectStrategy(retries) {
        if (initializing && retries >= 3) {
          return new Error('Initial Redis connection attempts exhausted');
        }
        return Math.min(retries * 100, 1000);
      }
    }
  });
  redisClient.on("error", (error) => {
    console.error("Persistent Redis connection error", {
      code: error.code || error.name || "UNKNOWN"
    });
  });
  try {
    await redisClient.connect();
    await redisClient.ping();
    initializing = false;
    sessionStore = new RedisStore({
      client: redisClient,
      prefix: "luminicent:web-session:",
    });
    console.log("Persistent Redis session and scan storage connected.");
  } catch {
    initializing = false;
    if (redisClient.isOpen) redisClient.destroy();
    throw new Error("Persistent Redis storage is unavailable; startup aborted");
  }
};

await initializeSessionStore();

const server = http.createServer(app);
configureProxyTrust(app, securityConfig);
const io = new socketIO(server, {
  cors: {
    origin: checkOrigin,
    methods: ["GET", "POST"],
    credentials: true,
  },
});

const orchestrator = new DockerOrchestrator(io, {
  executionMode: securityConfig.executionMode,
  buildNetwork: securityConfig.buildNetwork
});
const sessionRegistry = createRedisSessionRegistry({
  client: redisClient,
  onDelete: (sessionId) => io.in(sessionId).socketsLeave(sessionId)
});
const scanRecordStore = createRedisScanRecordStore({ client: redisClient });
const HOST = securityConfig.host;
const PORT = process.env.PORT || 5000;

app.get("/", (_req, res) => {
  res.send("Luminicent backend is running.");
});

app.get("/api/health", (_req, res) => {
  const ready = redisClient?.isReady === true;
  res.status(ready ? 200 : 503).json({
    ok: ready,
    status: ready ? "persistence-ready" : "unavailable",
    persistenceReady: ready,
    scanExecutionAvailable: false,
    timestamp: new Date().toISOString(),
  });
});

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Luminicent-Session-Id",
      "X-Luminicent-Session-Token",
    ],
  }),
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
const sessionMiddleware = session({
  name: sessionCookieName,
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  store: sessionStore,
  cookie: createSessionCookieOptions(process.env, securityConfig),
});
app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

app.use((req, res, next) => {
  req.io = io;
  req.orchestrator = orchestrator;
  req.sessionRegistry = sessionRegistry;
  req.scanRecordStore = scanRecordStore;
  next();
});

app.use("/api", uploadRoutes);
app.use("/api/github", githubRoutes);
app.use("/auth/github", githubRoutes);

registerSessionSocketHandlers(io, sessionRegistry);

app.use((err, req, res, next) => {
  console.error("Request failed", {
    method: req.method,
    path: req.path,
    code: err.code || err.name || "UNKNOWN",
  });
  if (res.headersSent) {
    next(err);
    return;
  }
  res.status(500).json({ error: "Internal server error" });
});

server.listen(PORT, HOST, () => {
  const boundary = securityConfig.tlsProxyMode
    ? ' Backend access must be through the configured trusted TLS-terminating proxy.'
    : '';
  console.log(`Server listening on configured interface ${HOST}:${PORT}.${boundary}`);
});

const shutdown = (signal) => {
  console.log(`Received ${signal}; closing the server and cleaning Docker sessions.`);
  io.close(() => {
    sessionRegistry.close();
    orchestrator.cleanupAll().catch((error) => {
      console.error('Docker session cleanup during shutdown failed', {
        code: error.code || error.name || 'UNKNOWN'
      });
      process.exitCode = 1;
    });
    if (redisClient.isOpen) {
      redisClient.quit().catch((error) => {
        console.error("Persistent Redis shutdown failed", {
          code: error.code || error.name || "UNKNOWN"
        });
        process.exitCode = 1;
      });
    }
  });
};

process.once("SIGINT", () => shutdown("SIGINT"));
process.once("SIGTERM", () => shutdown("SIGTERM"));

export { app, io };
