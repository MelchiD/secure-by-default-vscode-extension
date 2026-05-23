import { SecurityRule } from "../scanner/ruleEngine";
import { Issue } from "../models/issue";

export const corsRule: SecurityRule = {
  name: "insecure-cors",

  check(path): Issue | null {
    const node: any = path.node;

    // Detect cors()
    if (
      node.callee &&
      node.callee.type === "Identifier" &&
      node.callee.name === "cors"
    ) {
      const args = node.arguments || [];

      // bare cors()
      if (args.length === 0) {
        return {
          message:
            "Insecure CORS configuration detected: cors() may allow all origins by default.",
          line: node.loc?.start?.line ?? 1,
          severity: "warning",
          rule: "CORS_INSECURE_DEFAULT",
        };
      }

      // cors({ ... })
      const firstArg = args[0];
      if (firstArg.type === "ObjectExpression") {
        let hasWildcardOrigin = false;
        let hasCredentialsTrue = false;
        let hasOriginTrue = false;

        for (const prop of firstArg.properties) {
          if (prop.type !== "ObjectProperty") continue;

          const keyName =
            prop.key.type === "Identifier"
              ? prop.key.name
              : prop.key.type === "StringLiteral"
              ? prop.key.value
              : "";

          if (keyName === "origin") {
            if (
              prop.value.type === "StringLiteral" &&
              prop.value.value === "*"
            ) {
              hasWildcardOrigin = true;
            }

            if (
              prop.value.type === "BooleanLiteral" &&
              prop.value.value === true
            ) {
              hasOriginTrue = true;
            }
          }

          if (
            keyName === "credentials" &&
            prop.value.type === "BooleanLiteral" &&
            prop.value.value === true
          ) {
            hasCredentialsTrue = true;
          }
        }

        if (hasWildcardOrigin && hasCredentialsTrue) {
          return {
            message:
              'Unsafe CORS configuration detected: origin "*" is used together with credentials: true.',
            line: node.loc?.start?.line ?? 1,
            severity: "warning",
            rule: "CORS_WILDCARD_CREDENTIALS",
          };
        }

        if (hasWildcardOrigin) {
          return {
            message:
              'Overly permissive CORS configuration detected: origin "*" allows any website to access this API.',
            line: node.loc?.start?.line ?? 1,
            severity: "warning",
            rule: "CORS_WILDCARD_ORIGIN",
          };
        }

        if (hasOriginTrue) {
          return {
            message:
              "Potentially unsafe CORS configuration detected: origin: true reflects the request origin dynamically.",
            line: node.loc?.start?.line ?? 1,
            severity: "warning",
            rule: "CORS_ORIGIN_TRUE",
          };
        }
      }
    }

    return null;
  },
};