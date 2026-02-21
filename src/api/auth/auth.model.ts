import { extendZodWithOpenApi } from "@asteasolutions/zod-to-openapi";
import { z } from "zod";

extendZodWithOpenApi(z);

// ─── Admin Response Model ─────────────────────────────────────────────────────

export const AdminResponseModel = z
    .object({
        id: z.string().uuid().openapi({ example: "550e8400-e29b-41d4-a716-446655440000" }),
        name: z.string().openapi({ example: "John Doe" }),
        email: z.string().email().openapi({ example: "admin@toursandtravels.com" }),
        role: z.enum(["SUPER_ADMIN", "ADMIN"]).openapi({ example: "ADMIN" }),
        isActive: z.boolean().openapi({ example: true }),
        createdAt: z.string().openapi({ example: "2024-01-01T00:00:00.000Z" }),
        updatedAt: z.string().openapi({ example: "2024-01-01T00:00:00.000Z" }),
    })
    .openapi("Admin");

// ─── Auth Response Model ──────────────────────────────────────────────────────

export const AuthResponseModel = z
    .object({
        admin: AdminResponseModel,
        accessToken: z.string().openapi({ example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }),
        refreshToken: z.string().openapi({ example: "dGhpc2lzYXJlZnJlc2h0b2tlbg..." }),
    })
    .openapi("AuthResponse");

// ─── Message-only Response ────────────────────────────────────────────────────

export const MessageResponseModel = z
    .object({
        message: z.string().openapi({ example: "Operation successful" }),
    })
    .openapi("MessageResponse");
