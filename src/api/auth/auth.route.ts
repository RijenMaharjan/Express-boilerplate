import { OpenAPIRegistry } from "@asteasolutions/zod-to-openapi";
import express, { type Router } from "express";
import { z } from "zod";
import { createApiResponse } from "src/api-docs/openAPIResponseBuilders";
import { validateRequest } from "src/common/utils/httpHandlers";
import { authenticate } from "src/common/middleware/authenticate";
import { AuthController } from "./auth.controller";
import {
    RegisterSchema,
    LoginSchema,
    ForgotPasswordSchema,
    VerifyOtpSchema,
    ResetPasswordSchema,
} from "./auth.schema";
import { AdminResponseModel, AuthResponseModel, MessageResponseModel } from "./auth.model";

export const authRegistry = new OpenAPIRegistry();
export const authRouter: Router = express.Router();

const controller = new AuthController();

// ─── Register OpenAPI response schemas ──────────────────────────────────────

authRegistry.register("Admin", AdminResponseModel);
authRegistry.register("AuthResponse", AuthResponseModel);
authRegistry.register("MessageResponse", MessageResponseModel);

// ─── POST /register ─────────────────────────────────────────────────────────

authRegistry.registerPath({
    method: "post",
    path: "/api/v1/auth/register",
    tags: ["Auth"],
    summary: "Register a new admin account",
    request: {
        body: {
            content: {
                "application/json": {
                    schema: RegisterSchema.shape.body,
                },
            },
        },
    },
    responses: createApiResponse(AuthResponseModel, "Admin registered successfully", 201),
});

authRouter.post(
    "/register",
    validateRequest(RegisterSchema),
    controller.register,
);

// ─── POST /login ────────────────────────────────────────────────────────────

authRegistry.registerPath({
    method: "post",
    path: "/api/v1/auth/login",
    tags: ["Auth"],
    summary: "Login and receive httpOnly cookies (accessToken + refreshToken)",
    request: {
        body: {
            content: {
                "application/json": {
                    schema: LoginSchema.shape.body,
                },
            },
        },
    },
    responses: {
        ...createApiResponse(AuthResponseModel, "Logged in successfully"),
        401: {
            description: "Invalid credentials",
        },
    },
});

authRouter.post(
    "/login",
    validateRequest(LoginSchema),
    controller.login,
);

// ─── POST /refresh-token ─────────────────────────────────────────────────────

authRegistry.registerPath({
    method: "post",
    path: "/api/v1/auth/refresh-token",
    tags: ["Auth"],
    summary: "Refresh access token using httpOnly refresh token cookie",
    responses: {
        ...createApiResponse(z.null(), "Tokens refreshed; new cookies set"),
        401: { description: "Invalid or expired refresh token" },
    },
});

authRouter.post("/refresh-token", controller.refreshToken);

// ─── POST /logout ────────────────────────────────────────────────────────────

authRegistry.registerPath({
    method: "post",
    path: "/api/v1/auth/logout",
    tags: ["Auth"],
    summary: "Logout and clear auth cookies",
    security: [{ bearerAuth: [] }],
    responses: createApiResponse(z.null(), "Logged out successfully"),
});

authRouter.post("/logout", authenticate, controller.logout);

// ─── POST /forgot-password ───────────────────────────────────────────────────

authRegistry.registerPath({
    method: "post",
    path: "/api/v1/auth/forgot-password",
    tags: ["Auth"],
    summary: "Send OTP to email for password reset",
    request: {
        body: {
            content: {
                "application/json": {
                    schema: ForgotPasswordSchema.shape.body,
                },
            },
        },
    },
    responses: createApiResponse(z.null(), "OTP sent if email is registered"),
});

authRouter.post(
    "/forgot-password",
    validateRequest(ForgotPasswordSchema),
    controller.forgotPassword,
);

// ─── POST /verify-otp ────────────────────────────────────────────────────────

authRegistry.registerPath({
    method: "post",
    path: "/api/v1/auth/verify-otp",
    tags: ["Auth"],
    summary: "Verify OTP before resetting password",
    request: {
        body: {
            content: {
                "application/json": {
                    schema: VerifyOtpSchema.shape.body,
                },
            },
        },
    },
    responses: {
        ...createApiResponse(z.null(), "OTP verified successfully"),
        400: { description: "Invalid or expired OTP" },
    },
});

authRouter.post(
    "/verify-otp",
    validateRequest(VerifyOtpSchema),
    controller.verifyOtp,
);

// ─── POST /reset-password ────────────────────────────────────────────────────

authRegistry.registerPath({
    method: "post",
    path: "/api/v1/auth/reset-password",
    tags: ["Auth"],
    summary: "Reset password using verified OTP",
    request: {
        body: {
            content: {
                "application/json": {
                    schema: ResetPasswordSchema.shape.body,
                },
            },
        },
    },
    responses: {
        ...createApiResponse(z.null(), "Password reset successfully"),
        400: { description: "Invalid or expired OTP" },
    },
});

authRouter.post(
    "/reset-password",
    validateRequest(ResetPasswordSchema),
    controller.resetPassword,
);

// ─── GET /me ─────────────────────────────────────────────────────────────────

authRegistry.registerPath({
    method: "get",
    path: "/api/v1/auth/me",
    tags: ["Auth"],
    summary: "Get currently authenticated admin profile",
    security: [{ bearerAuth: [] }],
    responses: {
        ...createApiResponse(AdminResponseModel, "Admin profile fetched successfully"),
        401: { description: "Unauthorized" },
    },
});

authRouter.get("/me", authenticate, controller.getMe);
