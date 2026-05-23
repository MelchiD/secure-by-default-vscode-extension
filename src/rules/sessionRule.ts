import { File, ObjectExpression, ObjectProperty } from "@babel/types";
import traverse from "@babel/traverse";
import { Issue } from "../models/issue";
import { FileSecurityRule } from "../scanner/fileRuleEngine";

function getObjectProperty(
  obj: ObjectExpression,
  name: string
): ObjectProperty | null {
  for (const prop of obj.properties) {
    if (
      prop.type === "ObjectProperty" &&
      (
        (prop.key.type === "Identifier" && prop.key.name === name) ||
        (prop.key.type === "StringLiteral" && prop.key.value === name)
      )
    ) {
      return prop;
    }
  }
  return null;
}

function isBooleanTrueProperty(obj: ObjectExpression, name: string): boolean {
  const prop = getObjectProperty(obj, name);
  return !!(
    prop &&
    prop.value &&
    prop.value.type === "BooleanLiteral" &&
    prop.value.value === true
  );
}

function isHardcodedSecret(prop: ObjectProperty | null): boolean {
  if (!prop) return false;

  const value: any = prop.value;

  return (
    value.type === "StringLiteral" ||
    (value.type === "TemplateLiteral" && value.expressions.length === 0)
  );
}

function isWeakSecret(prop: ObjectProperty | null): boolean {
  if (!prop) return false;

  const value: any = prop.value;

  if (value.type === "StringLiteral") {
    const secret = value.value.toLowerCase();
    return [
      "123",
      "1234",
      "secret",
      "mysecret",
      "password",
      "changeme",
      "test",
    ].includes(secret);
  }

  return false;
}

export const sessionRule: FileSecurityRule = {
  name: "session-security",

  check(ast: File): Issue[] {
    const issues: Issue[] = [];

    traverse(ast, {
      CallExpression(path) {
        const node: any = path.node;

        if (
          node.callee &&
          node.callee.type === "Identifier" &&
          node.callee.name === "session"
        ) {
          const args = node.arguments || [];
          const firstArg = args[0];

          if (!firstArg || firstArg.type !== "ObjectExpression") {
            issues.push({
              message:
                "Session security issue: session() is used without a configuration object.",
              line: node.loc?.start?.line ?? 1,
              severity: "warning",
              rule: "SESSION_CONFIG_MISSING",
            });
            return;
          }

          const config = firstArg as ObjectExpression;

          const secretProp = getObjectProperty(config, "secret");
          const storeProp = getObjectProperty(config, "store");
          const saveUninitializedProp = getObjectProperty(
            config,
            "saveUninitialized"
          );
          const resaveProp = getObjectProperty(config, "resave");
          const cookieProp = getObjectProperty(config, "cookie");

          // secret missing
          if (!secretProp) {
            issues.push({
              message:
                "Session security issue: session secret is missing.",
              line: node.loc?.start?.line ?? 1,
              severity: "warning",
              rule: "SESSION_SECRET_MISSING",
            });
          }

          // hardcoded secret
          if (isHardcodedSecret(secretProp)) {
            issues.push({
              message:
                "Hardcoded session secret detected: store secrets in environment variables or a secure secret manager.",
              line: secretProp?.loc?.start?.line ?? node.loc?.start?.line ?? 1,
              severity: "warning",
              rule: "SESSION_SECRET_HARDCODED",
            });
          }

          // weak secret
          if (isWeakSecret(secretProp)) {
            issues.push({
              message:
                "Weak session secret detected: use a strong unpredictable secret.",
              line: secretProp?.loc?.start?.line ?? node.loc?.start?.line ?? 1,
              severity: "warning",
              rule: "SESSION_SECRET_WEAK",
            });
          }

          // saveUninitialized: true
          if (
            saveUninitializedProp &&
            saveUninitializedProp.value.type === "BooleanLiteral" &&
            saveUninitializedProp.value.value === true
          ) {
            issues.push({
              message:
                "Session configuration issue: saveUninitialized: true may create unnecessary sessions for anonymous users.",
              line:
                saveUninitializedProp.loc?.start?.line ??
                node.loc?.start?.line ??
                1,
              severity: "warning",
              rule: "SESSION_SAVEUNINITIALIZED_TRUE",
            });
          }

          // resave: true
          if (
            resaveProp &&
            resaveProp.value.type === "BooleanLiteral" &&
            resaveProp.value.value === true
          ) {
            issues.push({
              message:
                "Session configuration issue: resave: true may cause unnecessary session writes.",
              line: resaveProp.loc?.start?.line ?? node.loc?.start?.line ?? 1,
              severity: "warning",
              rule: "SESSION_RESAVE_TRUE",
            });
          }

          // missing custom store
          if (!storeProp) {
            issues.push({
              message:
                "Production concern: no custom session store configured. Express default MemoryStore is not recommended for production.",
              line: node.loc?.start?.line ?? 1,
              severity: "warning",
              rule: "SESSION_MEMORYSTORE_DEFAULT",
            });
          }

          // cookie checks
          if (cookieProp && cookieProp.value.type === "ObjectExpression") {
            const cookieObj = cookieProp.value as ObjectExpression;

            const hasSecure = isBooleanTrueProperty(cookieObj, "secure");
            const hasHttpOnly = isBooleanTrueProperty(cookieObj, "httpOnly");
            const sameSiteProp = getObjectProperty(cookieObj, "sameSite");

            if (!hasSecure) {
              issues.push({
                message:
                  "Session security issue: cookie.secure is missing or not set to true.",
                line: cookieProp.loc?.start?.line ?? node.loc?.start?.line ?? 1,
                severity: "warning",
                rule: "SESSION_COOKIE_SECURE_MISSING",
              });
            }

            if (!hasHttpOnly) {
              issues.push({
                message:
                  "Session security issue: cookie.httpOnly is missing or not set to true.",
                line: cookieProp.loc?.start?.line ?? node.loc?.start?.line ?? 1,
                severity: "warning",
                rule: "SESSION_COOKIE_HTTPONLY_MISSING",
              });
            }

            if (!sameSiteProp) {
              issues.push({
                message:
                  "Session security issue: cookie.sameSite is not set. This may weaken CSRF protection.",
                line: cookieProp.loc?.start?.line ?? node.loc?.start?.line ?? 1,
                severity: "warning",
                rule: "SESSION_COOKIE_SAMESITE_MISSING",
              });
            }
          } else {
            issues.push({
              message:
                "Session security issue: cookie settings are missing.",
              line: node.loc?.start?.line ?? 1,
              severity: "warning",
              rule: "SESSION_COOKIE_CONFIG_MISSING",
            });
          }
        }
      },
    });

    return issues;
  },
};