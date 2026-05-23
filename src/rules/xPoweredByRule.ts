import { File } from "@babel/types";
import traverse from "@babel/traverse";
import { Issue } from "../models/issue";
import { FileSecurityRule } from "../scanner/fileRuleEngine";

export const xPoweredByRule: FileSecurityRule = {
  name: "missing-x-powered-by-disable",

  check(ast: File): Issue[] {
    let hasExpressApp = false;
    let expressLine = 1;
    let hasDisableXPoweredBy = false;

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
          node.callee.type === "MemberExpression" &&
          node.callee.object &&
          node.callee.object.type === "Identifier" &&
          node.callee.object.name === "app" &&
          node.callee.property &&
          node.callee.property.type === "Identifier" &&
          node.callee.property.name === "disable" &&
          node.arguments &&
          node.arguments.length > 0 &&
          node.arguments[0].type === "StringLiteral" &&
          node.arguments[0].value === "x-powered-by"
        ) {
          hasDisableXPoweredBy = true;
        }
      },
    });

    if (hasExpressApp && !hasDisableXPoweredBy) {
      return [
        {
          message:
            'Missing app.disable("x-powered-by"): framework fingerprinting may expose Express usage to attackers.',
          line: expressLine,
          severity: "warning",
          rule: "X_POWERED_BY_NOT_DISABLED",
        },
      ];
    }

    return [];
  },
};