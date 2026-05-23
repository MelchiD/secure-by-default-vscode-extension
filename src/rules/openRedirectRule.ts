import { SecurityRule } from "../scanner/ruleEngine";
import { Issue } from "../models/issue";

function isReqUserControlledInput(node: any): boolean {
  if (!node || node.type !== "MemberExpression") return false;

  // req.query.next / req.body.url / req.params.returnTo
  if (
    node.object &&
    node.object.type === "MemberExpression" &&
    node.object.object &&
    node.object.object.type === "Identifier" &&
    node.object.object.name === "req" &&
    node.object.property &&
    node.object.property.type === "Identifier" &&
    ["query", "body", "params"].includes(node.object.property.name)
  ) {
    return true;
  }

  return false;
}

export const openRedirectRule: SecurityRule = {
  name: "open-redirect",

  check(path): Issue | null {
    const node: any = path.node;

    if (
      node.callee &&
      node.callee.type === "MemberExpression" &&
      node.callee.object &&
      node.callee.object.type === "Identifier" &&
      node.callee.object.name === "res" &&
      node.callee.property &&
      node.callee.property.type === "Identifier" &&
      node.callee.property.name === "redirect" &&
      node.arguments &&
      node.arguments.length > 0
    ) {
      const target = node.arguments[0];

      if (isReqUserControlledInput(target)) {
        return {
          message:
            "Potential open redirect detected: redirect target appears to come directly from user-controlled input.",
          line: node.loc?.start?.line ?? 1,
          severity: "warning",
          rule: "OPEN_REDIRECT",
        };
      }
    }

    return null;
  },
};