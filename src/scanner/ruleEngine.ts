import { NodePath } from "@babel/traverse";
import { Issue } from "../models/issue";
import { corsRule } from "../rules/corsRule";
import { jsonLimitRule } from "../rules/jsonLimitRule";
import { trustProxyRule } from "../rules/trustProxyRule";
import { uploadSizeLimitRule } from "../rules/uploadSizeLimitRule";
import { staticBroadPathRule } from "../rules/staticBroadPathRule";
import { openRedirectRule } from "../rules/openRedirectRule";

export interface SecurityRule {
  name: string;
  check(path: NodePath<any>): Issue | null;
}

export const rules: SecurityRule[] = [
  corsRule,
  jsonLimitRule,
  trustProxyRule,
  uploadSizeLimitRule,
  staticBroadPathRule,
  openRedirectRule,
];