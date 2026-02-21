import dotenv from "dotenv";
import { cleanEnv, host, num, port, str, testOnly } from "envalid";

dotenv.config();

export const env = cleanEnv(process.env, {
  NODE_ENV: str({
    devDefault: testOnly("test"),
    choices: ["development", "production", "test"],
  }),
  HOST: host({ devDefault: testOnly("localhost") }),
  PORT: port({ devDefault: testOnly(3000) }),
  CORS_ORIGIN: str({ devDefault: testOnly("http://localhost:3000") }),
  COMMON_RATE_LIMIT_MAX_REQUESTS: num({ devDefault: testOnly(1000) }),
  COMMON_RATE_LIMIT_WINDOW_MS: num({ devDefault: testOnly(1000) }),

  // JWT
  JWT_SECRET: str({ devDefault: testOnly("dev_jwt_secret") }),
  JWT_REFRESH_SECRET: str({ devDefault: testOnly("dev_refresh_secret") }),
  JWT_EXPIRES_IN: str({ devDefault: testOnly("15m") }),
  JWT_REFRESH_EXPIRES_IN: str({ devDefault: testOnly("7d") }),

  // SMTP
  SMTP_HOST: str({ devDefault: testOnly("smtp.gmail.com") }),
  SMTP_PORT: num({ devDefault: testOnly(587) }),
  SMTP_USER: str({ devDefault: testOnly("dev@example.com") }),
  SMTP_PASS: str({ devDefault: testOnly("dev_pass") }),
  SMTP_FROM: str({ devDefault: testOnly("Tours & Travels <dev@example.com>") }),
});
