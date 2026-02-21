import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { StatusCodes } from "http-status-codes";
import { env } from "src/common/utils/envConfig";
import { ServiceResponse } from "src/common/models/serviceResponse";
import { handleServiceResponse } from "src/common/utils/httpHandlers";

export interface AuthenticatedRequest extends Request {
    admin?: { id: string; role: string };
}

export const authenticate = (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
): void => {
    // Try Authorization header first (for Swagger/Postman), then cookie
    const headerToken = req.headers.authorization?.startsWith("Bearer ")
        ? req.headers.authorization.split(" ")[1]
        : undefined;

    const token = headerToken ?? (req.cookies as Record<string, string>)?.accessToken;

    if (!token) {
        const response = ServiceResponse.failure(
            "No token provided. Please login.",
            null,
            StatusCodes.UNAUTHORIZED,
        );
        handleServiceResponse(response, res);
        return;
    }

    try {
        const payload = jwt.verify(token, env.JWT_SECRET) as { id: string; role: string };
        req.admin = { id: payload.id, role: payload.role };
        next();
    } catch {
        const response = ServiceResponse.failure(
            "Invalid or expired access token",
            null,
            StatusCodes.UNAUTHORIZED,
        );
        handleServiceResponse(response, res);
    }
};
