import { SecurityRule } from "../scanner/ruleEngine";
import { Issue } from "../models/issue";

export const trustProxyRule: SecurityRule = {
  name: "unsafe-trust-proxy",

  check(path): Issue | null {
    const node: any = path.node;

    if (
      node.callee &&
      node.callee.type === "MemberExpression" &&
      node.callee.object &&
      node.callee.object.type === "Identifier" &&
      node.callee.object.name === "app" &&
      node.callee.property &&
      node.callee.property.type === "Identifier" &&
      node.callee.property.name === "set" &&
      node.arguments &&
      node.arguments.length >= 2 &&
      node.arguments[0].type === "StringLiteral" &&
      node.arguments[0].value === "trust proxy" &&
      node.arguments[1].type === "BooleanLiteral" &&
      node.arguments[1].value === true
    ) {
      return {
        message:
          'Overly broad trust proxy configuration detected: app.set("trust proxy", true) may trust forwarded IP headers too widely.',
        line: node.loc?.start?.line ?? 1,
        severity: "warning",
        rule: "TRUST_PROXY_TRUE",
      };
    }

    return null;
  },
};