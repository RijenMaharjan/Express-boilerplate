import {
  OpenAPIRegistry,
  OpenApiGeneratorV3,
} from "@asteasolutions/zod-to-openapi";
import { healthCheckRegistry } from "src/api/healthCheck/healthCheckRouter";
import { authRegistry } from "src/api/auth/auth.route";

export function generateOpenAPIDocument() {
  const registry = new OpenAPIRegistry([healthCheckRegistry, authRegistry]);

  registry.registerComponent("securitySchemes", "bearerAuth", {
    type: "http",
    scheme: "bearer",
    bearerFormat: "JWT", // Optional but good to have
  });
  const generator = new OpenApiGeneratorV3(registry.definitions);

  const document = generator.generateDocument({
    openapi: "3.0.0",
    info: {
      version: "1.0.0",
      title: "Swagger API",
    },
    security: [{ bearerAuth: [] }], // ✅ applies JWT auth globally
  });

  // (document as any).components = {
  //   securitySchemes: {
  //     bearerAuth: {
  //       type: "http",
  //       scheme: "bearer",
  //       bearerFormat: "JWT",
  //     },
  //   },
  // };

  // (document as any).security = [
  //   {
  //     bearerAuth: [],
  //   },
  // ];

  return document;
}
