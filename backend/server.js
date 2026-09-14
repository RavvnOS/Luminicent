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

// Load environment variables
dotenv.config();

const app = express();
const isProduction = process.env.NODE_ENV === "production";
const allowedOrigins = (
  process.env.CORS_ORIGIN ||
  "http://localhost:5173,http://localhost:3000,http://localhost:5000"
)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);
const sessionCookieName =
  process.env.SESSION_COOKIE_NAME || "luminicent_session";
const sessionSecret =
  process.env.SESSION_SECRET ||
  "luminicent-session-secret-change-this-in-production";
const sessionTtlMs = Number(process.env.SESSION_TTL_SECONDS || 86400) * 1000;
const sessionSecure =
  process.env.SESSION_SECURE !== undefined
    ? process.env.SESSION_SECURE === "true"
    : isProduction;
const sessionSameSite =
  process.env.SESSION_SAME_SITE || (isProduction ? "none" : "lax");

const checkOrigin = (origin, callback) => {
  if (!origin) return callback(null, true);
  if (allowedOrigins.includes(origin)) return callback(null, true);
  return callback(new Error("Not allowed by CORS"));
};

let sessionStore = undefined;
const initializeSessionStore = async () => {
  if (!process.env.REDIS_URL) {
    return;
  }

  try {
    const redisClient = createClient({ url: process.env.REDIS_URL });
    await redisClient.connect();
    sessionStore = new RedisStore({
      client: redisClient,
      prefix: "luminicent:",
    });
    console.log("Redis session store connected.");
  } catch (error) {
    console.warn(
      "Redis session store unavailable, using in-memory session storage for this process.",
      error.message,
    );
  }
};

await initializeSessionStore();

const server = http.createServer(app);
const io = new socketIO(server, {
  cors: {
    origin: checkOrigin,
    methods: ["GET", "POST"],
    credentials: true,
  },
});

const orchestrator = new DockerOrchestrator(io);
const HOST = process.env.HOST || "0.0.0.0";
const PORT = process.env.PORT || 5000;

app.get("/", (_req, res) => {
  res.send("Luminicent backend is running.");
});

app.get("/api/health", (_req, res) => {
  res.json({
    ok: true,
    status: "healthy",
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
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(
  session({
    name: sessionCookieName,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    store: sessionStore,
    cookie: {
      httpOnly: true,
      secure: sessionSecure,
      sameSite: sessionSameSite,
      maxAge: sessionTtlMs,
      path: "/",
      domain: process.env.COOKIE_DOMAIN || undefined,
    },
  }),
);

app.use((req, res, next) => {
  req.io = io;
  req.orchestrator = orchestrator;
  next();
});

app.use("/api", uploadRoutes);
app.use("/api/github", githubRoutes);
app.use("/auth/github", githubRoutes);

io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);

  socket.on("joinSession", ({ sessionId }) => {
    if (sessionId) {
      socket.join(sessionId);
      console.log(`Socket ${socket.id} joined session ${sessionId}`);
    }
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

app.use((err, req, res, next) => {
  console.error("Error:", err);
  res.status(500).json({ error: err.message || "Internal server error" });
});

server.listen(PORT, HOST, () => {
  console.log(`Server running on http://${HOST}:${PORT}`);
});

export { app, io };
