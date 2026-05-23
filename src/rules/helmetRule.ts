import { File } from "@babel/types";
import traverse from "@babel/traverse";
import { Issue } from "../models/issue";
import { FileSecurityRule } from "../scanner/fileRuleEngine";

export const helmetRule: FileSecurityRule = {
  name: "missing-helmet",

  check(ast: File): Issue[] {
    let hasExpressApp = false;
    let hasHelmet = false;
    let expressLine = 1;
    const issues: Issue[] = [];

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
          node.callee.name === "helmet"
        ) {
          hasHelmet = true;

          const args = node.arguments || [];
          const firstArg = args[0];

          if (firstArg && firstArg.type === "ObjectExpression") {
            for (const prop of firstArg.properties) {
              if (
                prop.type === "ObjectProperty" &&
                (
                  (prop.key.type === "Identifier" &&
                    prop.key.name === "contentSecurityPolicy") ||
                  (prop.key.type === "StringLiteral" &&
                    prop.key.value === "contentSecurityPolicy")
                ) &&
                prop.value.type === "BooleanLiteral" &&
                prop.value.value === false
              ) {
                issues.push({
                  message:
                    "Helmet configuration issue: contentSecurityPolicy is explicitly disabled.",
                  line: prop.loc?.start?.line ?? node.loc?.start?.line ?? 1,
                  severity: "warning",
                  rule: "HELMET_CSP_DISABLED",
                });
              }
            }
          }
        }
      },
    });

    if (hasExpressApp && !hasHelmet) {
      issues.push({
        message:
          "Missing Helmet middleware: Express application is not using helmet() to set secure HTTP headers.",
        line: expressLine,
        severity: "warning",
        rule: "HELMET_MISSING",
      });
    }

    return issues;
  },
};