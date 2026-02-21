import { Request, Response } from "express";
import { handleServiceResponse } from "src/common/utils/httpHandlers";
import { AuthService } from "./auth.service";
import { AuthenticatedRequest } from "src/common/middleware/authenticate";
import { env } from "src/common/utils/envConfig";

// Cookie options
const ACCESS_TOKEN_COOKIE_OPTIONS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    maxAge: 15 * 60 * 1000, // 15 minutes
};

const REFRESH_TOKEN_COOKIE_OPTIONS = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: "/api/v1/auth", // Restrict refresh token cookie scope
};

export class AuthController {
    private readonly service: AuthService;

    constructor() {
        this.service = new AuthService();
    }

    // ─── Register ───────────────────────────────────────────────────────────────

    register = async (req: Request, res: Response): Promise<void> => {
        const result = await this.service.register(req.body);
        handleServiceResponse(result, res);
    };

    // ─── Login ──────────────────────────────────────────────────────────────────

    login = async (req: Request, res: Response): Promise<void> => {
        const result = await this.service.login(req.body);

        if (result.success && result.responseObject) {
            const { accessToken, refreshToken } = result.responseObject as any;

            res.cookie("accessToken", accessToken, ACCESS_TOKEN_COOKIE_OPTIONS);
            res.cookie("refreshToken", refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);

            // Remove raw tokens from response body for security
            const {...safeData } = result.responseObject as any;
            // const { accessToken: _a, refreshToken: _r, ...safeData } = result.responseObject as any;
            handleServiceResponse({ ...result, responseObject: safeData }, res);
            return;
        }

        handleServiceResponse(result, res);
    };

    // ─── Refresh Token ──────────────────────────────────────────────────────────

    refreshToken = async (req: Request, res: Response): Promise<void> => {
        const token =
            (req.cookies as Record<string, string>)?.refreshToken ??
            req.body?.refreshToken;

        const result = await this.service.refreshToken(token ?? "");

        if (result.success && result.responseObject) {
            const { accessToken, refreshToken } = result.responseObject;
            res.cookie("accessToken", accessToken, ACCESS_TOKEN_COOKIE_OPTIONS);
            res.cookie("refreshToken", refreshToken, REFRESH_TOKEN_COOKIE_OPTIONS);
            handleServiceResponse({ ...result, responseObject: null }, res);
            return;
        }

        handleServiceResponse(result, res);
    };

    // ─── Logout ─────────────────────────────────────────────────────────────────

    logout = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
        const result = await this.service.logout(req.admin!.id);

        res.clearCookie("accessToken");
        res.clearCookie("refreshToken", { path: "/api/v1/auth" });

        handleServiceResponse(result, res);
    };

    // ─── Forgot Password ────────────────────────────────────────────────────────

    forgotPassword = async (req: Request, res: Response): Promise<void> => {
        const result = await this.service.forgotPassword(req.body);
        handleServiceResponse(result, res);
    };

    // ─── Verify OTP ─────────────────────────────────────────────────────────────

    verifyOtp = async (req: Request, res: Response): Promise<void> => {
        const result = await this.service.verifyOtp(req.body);
        handleServiceResponse(result, res);
    };

    // ─── Reset Password ─────────────────────────────────────────────────────────

    resetPassword = async (req: Request, res: Response): Promise<void> => {
        const result = await this.service.resetPassword(req.body);
        handleServiceResponse(result, res);
    };

    // ─── Get Me ─────────────────────────────────────────────────────────────────

    getMe = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
        const result = await this.service.getMe(req.admin!.id);
        handleServiceResponse(result, res);
    };
}
