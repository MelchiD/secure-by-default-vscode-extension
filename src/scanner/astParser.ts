
import * as parser from "@babel/parser";
import traverse from "@babel/traverse";
import { Issue } from "../models/issue";
import { rules } from "./ruleEngine";
import { fileRules } from "./fileRuleEngine";

export function scanCode(code: string): Issue[] {
  const ast = parser.parse(code, {
    sourceType: "unambiguous",
    plugins: ["jsx", "typescript"],
    errorRecovery: true,
  });

  const issues: Issue[] = [];

  for (const fileRule of fileRules) {
    issues.push(...fileRule.check(ast));
  }

  traverse(ast, {
    CallExpression(path) {
      for (const rule of rules) {
        const result = rule.check(path);
        if (result) {
          issues.push(result);
        }
      }
    },
  });

  return issues;
}