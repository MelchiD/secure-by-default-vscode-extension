import { SecurityRule } from "../scanner/ruleEngine";
import { Issue } from "../models/issue";

function parseLimitToBytes(limit: string): number | null {
  const match = limit.trim().match(/^(\d+)\s*(b|kb|mb|gb)$/i);
  if (!match) return null;

  const value = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case "b":
      return value;
    case "kb":
      return value * 1024;
    case "mb":
      return value * 1024 * 1024;
    case "gb":
      return value * 1024 * 1024 * 1024;
    default:
      return null;
  }
}

export const jsonLimitRule: SecurityRule = {
  name: "missing-json-limit",

  check(path): Issue | null {
    const node: any = path.node;

    if (
      node.callee &&
      node.callee.type === "MemberExpression" &&
      node.callee.object &&
      node.callee.object.type === "Identifier" &&
      node.callee.object.name === "express" &&
      node.callee.property &&
      node.callee.property.type === "Identifier" &&
      node.callee.property.name === "json"
    ) {
      const args = node.arguments || [];

      // express.json()
      if (args.length === 0) {
        return {
          message:
            "Missing JSON body size limit: express.json() is used without a limit option.",
          line: node.loc?.start?.line ?? 1,
          severity: "warning",
          rule: "JSON_LIMIT_MISSING",
        };
      }

      const firstArg = args[0];

      if (firstArg.type === "ObjectExpression") {
        const limitProp = firstArg.properties.find((prop: any) => {
          return (
            prop.type === "ObjectProperty" &&
            prop.key &&
            (
              (prop.key.type === "Identifier" && prop.key.name === "limit") ||
              (prop.key.type === "StringLiteral" && prop.key.value === "limit")
            )
          );
        });

        if (!limitProp) {
          return {
            message:
              "Missing JSON body size limit: express.json() configuration does not define a limit.",
            line: node.loc?.start?.line ?? 1,
            severity: "warning",
            rule: "JSON_LIMIT_MISSING",
          };
        }

        if (
          limitProp.value &&
          limitProp.value.type === "StringLiteral"
        ) {
          const bytes = parseLimitToBytes(limitProp.value.value);

          if (bytes !== null && bytes > 1024 * 1024) {
            return {
              message:
                "Large JSON body size limit detected: consider using a smaller request size limit unless large payloads are required.",
              line: node.loc?.start?.line ?? 1,
              severity: "warning",
              rule: "JSON_LIMIT_TOO_LARGE",
            };
          }
        }
      }
    }

    return null;
  },
};