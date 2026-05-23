import { SecurityRule } from "../scanner/ruleEngine";
import { Issue } from "../models/issue";

export const staticBroadPathRule: SecurityRule = {
  name: "broad-static-path",

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
      node.callee.property.name === "static"
    ) {
      const args = node.arguments || [];
      const firstArg = args[0];

      if (!firstArg) return null;

      const isDot =
        firstArg.type === "StringLiteral" && firstArg.value === ".";
      const isRoot =
        firstArg.type === "StringLiteral" && firstArg.value === "/";
      const isDirname =
        firstArg.type === "Identifier" && firstArg.name === "__dirname";

      if (isDot || isRoot || isDirname) {
        return {
          message:
            "Overly broad static file root detected: serving '.' , '/' or __dirname may unintentionally expose sensitive files.",
          line: node.loc?.start?.line ?? 1,
          severity: "warning",
          rule: "STATIC_BROAD_PATH",
        };
      }
    }

    return null;
  },
};