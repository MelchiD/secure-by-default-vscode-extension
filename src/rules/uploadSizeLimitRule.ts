import { SecurityRule } from "../scanner/ruleEngine";
import { Issue } from "../models/issue";

export const uploadSizeLimitRule: SecurityRule = {
  name: "missing-upload-size-limit",

  check(path): Issue | null {
    const node: any = path.node;

    if (
      node.callee &&
      node.callee.type === "Identifier" &&
      node.callee.name === "multer"
    ) {
      const args = node.arguments || [];

      // multer()
      if (args.length === 0) {
        return {
          message:
            "Upload middleware missing file size limit: multer() is used without limits.fileSize.",
          line: node.loc?.start?.line ?? 1,
          severity: "warning",
          rule: "UPLOAD_LIMIT_MISSING",
        };
      }

      const firstArg = args[0];

      if (firstArg.type === "ObjectExpression") {
        const limitsProp = firstArg.properties.find((prop: any) => {
          return (
            prop.type === "ObjectProperty" &&
            prop.key &&
            (
              (prop.key.type === "Identifier" && prop.key.name === "limits") ||
              (prop.key.type === "StringLiteral" && prop.key.value === "limits")
            )
          );
        });

        if (!limitsProp || limitsProp.value.type !== "ObjectExpression") {
          return {
            message:
              "Upload middleware missing file size limit: multer() configuration does not define limits.fileSize.",
            line: node.loc?.start?.line ?? 1,
            severity: "warning",
            rule: "UPLOAD_LIMIT_MISSING",
          };
        }

        const hasFileSize = limitsProp.value.properties.some((prop: any) => {
          return (
            prop.type === "ObjectProperty" &&
            prop.key &&
            (
              (prop.key.type === "Identifier" &&
                prop.key.name === "fileSize") ||
              (prop.key.type === "StringLiteral" &&
                prop.key.value === "fileSize")
            )
          );
        });

        if (!hasFileSize) {
          return {
            message:
              "Upload middleware missing file size limit: multer() configuration does not define limits.fileSize.",
            line: node.loc?.start?.line ?? 1,
            severity: "warning",
            rule: "UPLOAD_LIMIT_MISSING",
          };
        }
      }
    }

    return null;
  },
};