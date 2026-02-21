import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import crypto from "crypto";
import { StatusCodes } from "http-status-codes";
import { env } from "src/common/utils/envConfig";
import { ServiceResponse } from "src/common/models/serviceResponse";
import { AuthRepository } from "./auth.repository";
import {
    RegisterDto,
    LoginDto,
    ForgotPasswordDto,
    VerifyOtpDto,
    ResetPasswordDto,
    AdminDto,
    AuthResponseDto,
} from "./dto/auth.dto";

const SALT_ROUNDS = 12;
const OTP_EXPIRY_MINUTES = 10;

export class AuthService {
    private readonly repo: AuthRepository;

    constructor() {
        this.repo = new AuthRepository();
    }

    // ─── Token Helpers ──────────────────────────────────────────────────────────

    private signAccessToken(payload: { id: string; role: string }): string {
        return jwt.sign(payload, env.JWT_SECRET, {
            expiresIn: env.JWT_EXPIRES_IN as jwt.SignOptions["expiresIn"],
        });
    }

    private signRefreshToken(payload: { id: string }): string {
        return jwt.sign(payload, env.JWT_REFRESH_SECRET, {
            expiresIn: env.JWT_REFRESH_EXPIRES_IN as jwt.SignOptions["expiresIn"],
        });
    }

    private sanitizeAdmin(admin: {
        id: string;
        name: string;
        email: string;
        role: any;
        isActive: boolean;
        createdAt: Date;
        updatedAt: Date;
    }): AdminDto {
        return {
            id: admin.id,
            name: admin.name,
            email: admin.email,
            role: admin.role,
            isActive: admin.isActive,
            createdAt: admin.createdAt,
            updatedAt: admin.updatedAt,
        };
    }

    // ─── Mailer ─────────────────────────────────────────────────────────────────

    private createMailTransporter() {
        return nodemailer.createTransport({
            host: env.SMTP_HOST,
            port: env.SMTP_PORT,
            secure: env.SMTP_PORT === 465,
            auth: {
                user: env.SMTP_USER,
                pass: env.SMTP_PASS,
            },
        });
    }

    private async sendOtpEmail(to: string, otp: string): Promise<void> {
        const transporter = this.createMailTransporter();
        await transporter.sendMail({
            from: env.SMTP_FROM,
            to,
            subject: "Password Reset OTP – Tours & Travels",
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; padding: 24px; border: 1px solid #e0e0e0; border-radius: 8px;">
          <h2 style="color: #2d6a4f;">Tours & Travels</h2>
          <p>You requested a password reset. Use the OTP below. It expires in <strong>${OTP_EXPIRY_MINUTES} minutes</strong>.</p>
          <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center; padding: 16px; background: #f0f4f0; border-radius: 6px; margin: 16px 0;">
            ${otp}
          </div>
          <p style="color: #888; font-size: 12px;">If you did not request this, please ignore this email.</p>
        </div>
      `,
        });
    }

    // ─── Register ────────────────────────────────────────────────────────────────

    async register(
        data: RegisterDto,
    ): Promise<ServiceResponse<AuthResponseDto | null>> {
        const existing = await this.repo.findByEmail(data.email);
        if (existing) {
            return ServiceResponse.failure(
                "An account with this email already exists",
                null,
                StatusCodes.CONFLICT,
            );
        }

        const hashedPassword = await bcrypt.hash(data.password, SALT_ROUNDS);

        const admin = await this.repo.create({ ...data, password: hashedPassword });

        const accessToken = this.signAccessToken({ id: admin.id, role: admin.role });
        const refreshToken = this.signRefreshToken({ id: admin.id });
        await this.repo.updateRefreshToken(admin.id, refreshToken);

        return ServiceResponse.success<AuthResponseDto>(
            "Admin registered successfully",
            { admin: this.sanitizeAdmin(admin) },
            StatusCodes.CREATED,
        );
    }

    // ─── Login ───────────────────────────────────────────────────────────────────

    async login(
        data: LoginDto,
    ): Promise<
        ServiceResponse<{ admin: AdminDto; accessToken: string; refreshToken: string } | null>
    > {
        const admin = await this.repo.findByEmail(data.email);
        if (!admin) {
            return ServiceResponse.failure(
                "Invalid email or password",
                null,
                StatusCodes.UNAUTHORIZED,
            );
        }

        if (!admin.isActive) {
            return ServiceResponse.failure(
                "Your account has been deactivated. Please contact support.",
                null,
                StatusCodes.FORBIDDEN,
            );
        }

        const isPasswordValid = await bcrypt.compare(data.password, admin.password);
        if (!isPasswordValid) {
            return ServiceResponse.failure(
                "Invalid email or password",
                null,
                StatusCodes.UNAUTHORIZED,
            );
        }

        const accessToken = this.signAccessToken({ id: admin.id, role: admin.role });
        const refreshToken = this.signRefreshToken({ id: admin.id });
        await this.repo.updateRefreshToken(admin.id, refreshToken);

        return ServiceResponse.success(
            "Logged in successfully",
            { admin: this.sanitizeAdmin(admin), accessToken, refreshToken },
        );
    }

    // ─── Refresh Token ───────────────────────────────────────────────────────────

    async refreshToken(
        token: string,
    ): Promise<ServiceResponse<{ accessToken: string; refreshToken: string } | null>> {
        let payload: { id: string };

        try {
            payload = jwt.verify(token, env.JWT_REFRESH_SECRET) as { id: string };
        } catch {
            return ServiceResponse.failure(
                "Invalid or expired refresh token",
                null,
                StatusCodes.UNAUTHORIZED,
            );
        }

        const admin = await this.repo.findById(payload.id);
        if (!admin || admin.refreshToken !== token) {
            return ServiceResponse.failure(
                "Refresh token mismatch or account not found",
                null,
                StatusCodes.UNAUTHORIZED,
            );
        }

        const newAccessToken = this.signAccessToken({ id: admin.id, role: admin.role });
        const newRefreshToken = this.signRefreshToken({ id: admin.id });
        await this.repo.updateRefreshToken(admin.id, newRefreshToken);

        return ServiceResponse.success(
            "Tokens refreshed successfully",
            { accessToken: newAccessToken, refreshToken: newRefreshToken },
        );
    }

    // ─── Logout ──────────────────────────────────────────────────────────────────

    async logout(adminId: string): Promise<ServiceResponse<null>> {
        const admin = await this.repo.findById(adminId);
        if (!admin) {
            return ServiceResponse.failure("Admin not found", null, StatusCodes.NOT_FOUND);
        }
        await this.repo.updateRefreshToken(adminId, null);
        return ServiceResponse.success("Logged out successfully", null);
    }

    // ─── Forgot Password ──────────────────────────────────────────────────────────

    async forgotPassword(
        data: ForgotPasswordDto,
    ): Promise<ServiceResponse<null>> {
        const admin = await this.repo.findByEmail(data.email);

        // Always return success to avoid email enumeration
        if (!admin) {
            return ServiceResponse.success(
                "If this email is registered, you will receive an OTP shortly",
                null,
            );
        }

        const otp = crypto.randomInt(100000, 999999).toString();
        const expiry = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);

        await this.repo.updateResetOtp(admin.id, otp, expiry);

        try {
            await this.sendOtpEmail(admin.email, otp);
        } catch (err) {
            // Don't expose mail error to client
            console.error("[AuthService] Failed to send OTP email:", err);
        }

        return ServiceResponse.success(
            "If this email is registered, you will receive an OTP shortly",
            null,
        );
    }

    // ─── Verify OTP ──────────────────────────────────────────────────────────────

    async verifyOtp(data: VerifyOtpDto): Promise<ServiceResponse<null>> {
        const admin = await this.repo.findByEmail(data.email);

        if (
            !admin ||
            !admin.resetOtp ||
            !admin.resetOtpExpiry ||
            admin.resetOtp !== data.otp ||
            admin.resetOtpExpiry < new Date()
        ) {
            return ServiceResponse.failure(
                "Invalid or expired OTP",
                null,
                StatusCodes.BAD_REQUEST,
            );
        }

        return ServiceResponse.success("OTP verified successfully", null);
    }

    // ─── Reset Password ──────────────────────────────────────────────────────────

    async resetPassword(
        data: ResetPasswordDto,
    ): Promise<ServiceResponse<null>> {
        const admin = await this.repo.findByEmail(data.email);

        if (
            !admin ||
            !admin.resetOtp ||
            !admin.resetOtpExpiry ||
            admin.resetOtp !== data.otp ||
            admin.resetOtpExpiry < new Date()
        ) {
            return ServiceResponse.failure(
                "Invalid or expired OTP",
                null,
                StatusCodes.BAD_REQUEST,
            );
        }

        const hashedPassword = await bcrypt.hash(data.newPassword, SALT_ROUNDS);
        await this.repo.updatePassword(admin.id, hashedPassword);
        await this.repo.clearResetOtp(admin.id);
        // Invalidate any active sessions
        await this.repo.updateRefreshToken(admin.id, null);

        return ServiceResponse.success("Password reset successfully", null);
    }

    // ─── Get Me ──────────────────────────────────────────────────────────────────

    async getMe(adminId: string): Promise<ServiceResponse<AdminDto | null>> {
        const admin = await this.repo.findById(adminId);
        if (!admin) {
            return ServiceResponse.failure("Admin not found", null, StatusCodes.NOT_FOUND);
        }
        return ServiceResponse.success<AdminDto>(
            "Admin profile fetched successfully",
            this.sanitizeAdmin(admin),
        );
    }
}
