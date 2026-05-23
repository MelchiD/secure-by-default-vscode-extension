import { File } from "@babel/types";
import traverse from "@babel/traverse";
import { Issue } from "../models/issue";
import { FileSecurityRule } from "../scanner/fileRuleEngine";

export const rateLimitRule: FileSecurityRule = {
  name: "missing-rate-limit",

  check(ast: File): Issue[] {
    let hasExpressApp = false;
    let hasRateLimit = false;
    let expressLine = 1;

    traverse(ast, {
      VariableDeclarator(path) {
        const node: any = path.node;

        if (
          node.init &&
          node.init.type === "CallExpression" &&
          node.init.callee &&
          node.init.callee.type === "Identifier" &&
          node.init.callee.name === "express"
        ) {
          hasExpressApp = true;
          expressLine = node.loc?.start?.line ?? 1;
        }
      },

      CallExpression(path) {
        const node: any = path.node;

        if (
          node.callee &&
          node.callee.type === "Identifier" &&
          node.callee.name === "rateLimit"
        ) {
          hasRateLimit = true;
        }
      },
    });

    if (hasExpressApp && !hasRateLimit) {
      return [
        {
          message:
            "Missing rate limiting middleware: Express application does not appear to use rateLimit() to reduce brute-force and abuse risk.",
          line: expressLine,
          severity: "warning",
          rule: "RATE_LIMIT_MISSING",
        },
      ];
    }

    return [];
  },
};