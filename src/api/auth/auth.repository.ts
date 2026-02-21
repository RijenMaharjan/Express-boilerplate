import prisma from "src/config/prisma";
import { RegisterDto } from "./dto/auth.dto";

export class AuthRepository {
  // ─── Find ────────────────────────────────────────────────────────────────
  async findByEmail(email: string) {
    return prisma.user.findUnique({ where: { email } });
  }

  async findById(id: string) {
    return prisma.user.findUnique({ where: { id } });
  }

  // ─── Create ──────────────────────────────────────────────────────────────
  async create(data: RegisterDto) {
    return prisma.user.create({
      data: {
        email: data.email,
        password: data.password,
      },
    });
  }

  // ─── Token Management ────────────────────────────────────────────────────
  async updateRefreshToken(id: string, refreshToken: string | null) {
    await prisma.user.update({
      where: { id },
      data: { refreshToken },
    });
  }

  // ─── OTP Management ──────────────────────────────────────────────────────
  async updateResetOtp(id: string, otp: string, expiry: Date) {
    await prisma.user.update({
      where: { id },
      data: { resetOtp: otp, resetOtpExpiry: expiry },
    });
  }

  async clearResetOtp(id: string) {
    await prisma.user.update({
      where: { id },
      data: { resetOtp: null, resetOtpExpiry: null },
    });
  }

  // ─── Password ───────────────────────────────────────────────────────────
  async updatePassword(id: string, hashedPassword: string) {
    await prisma.user.update({
      where: { id },
      data: { password: hashedPassword },
    });
  }
}