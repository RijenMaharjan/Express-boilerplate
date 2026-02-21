import cors from "cors";
import express, { type Express } from "express";
import cookieParser from "cookie-parser";
// import helmet from "helmet";
import http from "node:http";
import path from "path";
import { healthCheckRouter } from "./api/healthCheck/healthCheckRouter";
import { authRouter } from "./api/auth/auth.route";
import { openAPIRouter } from "./api-docs/openAPIRouter";
import { pino } from "pino";
import { Server } from "socket.io";

import requestLogger from "./common/middleware/requestLogger";
import errorHandler from "./common/middleware/errorHandler";

// Logger
const logger = pino({ name: "server start" });

// --- Express app ---
export const app: Express = express();
app.set("trust proxy", true); // trust Render reverse proxy

// Serve static templates
app.use(express.static(path.join(__dirname, "../src/templates")));

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// --- CORS setup ---
const allowedOrigins: string[] = [
  "http://localhost:8080", // Swagger UI served from backend
  "http://localhost:3000", 
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true); // allow Postman / curl
      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        console.log("Blocked by CORS:", origin);
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);

// Security headers
// app.use(helmet());

// Request logging
app.use(requestLogger);
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`);
  next();
});

// --- Routes ---
app.use("/health-check", healthCheckRouter);
app.use("/api/v1/auth", authRouter);

// Swagger/OpenAPI
app.use(openAPIRouter);

// Error handler
app.use(errorHandler());

// --- HTTP Server + Socket.io ---
export const httpServer = http.createServer(app);

export const io = new Server(httpServer, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true,
  },
});


app.set("io", io);

export { logger };
