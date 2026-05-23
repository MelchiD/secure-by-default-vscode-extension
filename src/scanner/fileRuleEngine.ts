import { File } from "@babel/types";
import { Issue } from "../models/issue";
import { helmetRule } from "../rules/helmetRule";
import { rateLimitRule } from "../rules/rateLimitRule";
import { sessionRule } from "../rules/sessionRule";
import { xPoweredByRule } from "../rules/xPoweredByRule";

export interface FileSecurityRule {
  name: string;
  check(ast: File): Issue[];
}

export const fileRules: FileSecurityRule[] = [
  helmetRule,
  rateLimitRule,
  sessionRule,
  xPoweredByRule,
];