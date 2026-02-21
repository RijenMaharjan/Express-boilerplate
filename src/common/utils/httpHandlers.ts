import type { NextFunction, Request, Response } from "express";
import { StatusCodes } from "http-status-codes";
import type { ZodType } from "zod";
import { ServiceResponse } from "../models/serviceResponse";

export const handleServiceResponse = (
  serviceResponse: ServiceResponse<any>,
  response: Response,
) => {
  return response.status(serviceResponse.statusCode).send(serviceResponse);
};

export const validateRequest =
  (schema: ZodType) => (req: Request, res: Response, next: NextFunction) => {
    const check = schema.safeParse({
      body: req.body,
      query: req.query,
      params: req.params,
    });

    if (!check.success) {
      const errorDetails: Record<string, Record<string, string[]>> = {
        body: {},
      };

      // Zod v4 uses .issues (v3 used .errors)
      check.error.issues.forEach((issue) => {
        const field = issue.path.join(".");
        const fieldName = field.split(".")[1] ?? field;

        if (!errorDetails.body[fieldName]) {
          errorDetails.body[fieldName] = [];
        }

        errorDetails.body[fieldName].push(issue.message);
      });

      const statusCode = StatusCodes.BAD_REQUEST;
      const serviceResponse = ServiceResponse.failure(
        errorDetails,
        null,
        statusCode,
      );
      return handleServiceResponse(serviceResponse, res);
    } else {
      next();
    }
  };
