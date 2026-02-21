// ─── Role type (mirrors prisma schema enum) ───────────────────────────────────
export type Role = "SUPER_ADMIN" | "ADMIN";

// ─── Request DTOs ────────────────────────────────────────────────────────────

export interface RegisterDto {
    name: string;
    email: string;
    password: string;
    role?: Role;
}

export interface LoginDto {
    email: string;
    password: string;
}

export interface ForgotPasswordDto {
    email: string;
}

export interface VerifyOtpDto {
    email: string;
    otp: string;
}

export interface ResetPasswordDto {
    email: string;
    otp: string;
    newPassword: string;
}

// ─── Response DTOs ───────────────────────────────────────────────────────────

export interface AdminDto {
    id: string;
    name: string;
    email: string;
    role: Role;
    isActive: boolean;
    createdAt: Date;
    updatedAt: Date;
}

export interface AuthResponseDto {
    admin: AdminDto;
}
