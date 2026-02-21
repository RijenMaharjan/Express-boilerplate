import { extendZodWithOpenApi } from "@asteasolutions/zod-to-openapi";
import { z } from "zod";

extendZodWithOpenApi(z);

// ─── Register ────────────────────────────────────────────────────────────────

export const RegisterSchema = z.object({
    body: z.object({
        name: z
            .string()
            .min(2, "Name must be at least 2 characters")
            .max(100, "Name must not exceed 100 characters")
            .trim()
            .openapi({ example: "John Doe" }),

        email: z
            .string()
            .min(1, "Email is required")
            .email("Invalid email format")
            .openapi({ example: "admin@toursandtravels.com" }),

        password: z
            .string()
            .min(8, "Password must be at least 8 characters")
            .max(64, "Password must not exceed 64 characters")
            .regex(
                /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
                "Password must contain at least one uppercase letter, one lowercase letter, and one number",
            )
            .openapi({ example: "Admin@1234" }),
    }),
});

// ─── Login ───────────────────────────────────────────────────────────────────

export const LoginSchema = z.object({
    body: z.object({
        email: z
            .string()
            .min(1, "Email is required")
            .email("Invalid email format")
            .openapi({ example: "admin@toursandtravels.com" }),

        password: z
            .string()
            .min(1, "Password is required")
            .openapi({ example: "Admin@1234" }),
    }),
});

// ─── Forgot Password ──────────────────────────────────────────────────────────

export const ForgotPasswordSchema = z.object({
    body: z.object({
        email: z
            .string()
            .min(1, "Email is required")
            .email("Invalid email format")
            .openapi({ example: "admin@toursandtravels.com" }),
    }),
});

// ─── Verify OTP ──────────────────────────────────────────────────────────────

export const VerifyOtpSchema = z.object({
    body: z.object({
        email: z
            .string()
            .min(1, "Email is required")
            .email("Invalid email format")
            .openapi({ example: "admin@toursandtravels.com" }),

        otp: z
            .string()
            .length(6, "OTP must be exactly 6 digits")
            .regex(/^\d+$/, "OTP must contain only digits")
            .openapi({ example: "123456" }),
    }),
});

// ─── Reset Password ───────────────────────────────────────────────────────────

export const ResetPasswordSchema = z.object({
    body: z.object({
        email: z
            .string()
            .min(1, "Email is required")
            .email("Invalid email format")
            .openapi({ example: "admin@toursandtravels.com" }),

        otp: z
            .string()
            .length(6, "OTP must be exactly 6 digits")
            .regex(/^\d+$/, "OTP must contain only digits")
            .openapi({ example: "123456" }),

        newPassword: z
            .string()
            .min(8, "Password must be at least 8 characters")
            .max(64, "Password must not exceed 64 characters")
            .regex(
                /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
                "Password must contain at least one uppercase letter, one lowercase letter, and one number",
            )
            .openapi({ example: "NewAdmin@1234" }),
    }),
});
