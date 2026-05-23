import * as vscode from "vscode";
import { scanCode } from "./scanner/astParser";
import { SecurityCodeActionProvider } from "./securityCodeActionProvider";

export function activate(context: vscode.ExtensionContext) {
  vscode.window.showInformationMessage("Secure-by-Default extension activated");

  const collection =
    vscode.languages.createDiagnosticCollection("secure-default");

  const analyzeDocument = (document: vscode.TextDocument) => {
    if (
      document.languageId !== "javascript" &&
      document.languageId !== "typescript" &&
      document.languageId !== "javascriptreact" &&
      document.languageId !== "typescriptreact"
    ) {
      return;
    }

    const code = document.getText();
    const issues = scanCode(code);

    const diagnostics: vscode.Diagnostic[] = issues.map((issue) => {
      const line = Math.max(issue.line - 1, 0);
      const range = new vscode.Range(line, 0, line, 100);

      const severity =
        issue.severity === "error"
          ? vscode.DiagnosticSeverity.Error
          : vscode.DiagnosticSeverity.Warning;

      const diagnostic = new vscode.Diagnostic(
        range,
        issue.message,
        severity
      );

      diagnostic.source = "secure-default";
      diagnostic.code = issue.rule; // IMPORTANT: needed for quick fixes

      return diagnostic;
    });

    collection.set(document.uri, diagnostics);
  };

  if (vscode.window.activeTextEditor) {
    analyzeDocument(vscode.window.activeTextEditor.document);
  }

  context.subscriptions.push(
    collection,
    vscode.workspace.onDidOpenTextDocument(analyzeDocument),
    vscode.workspace.onDidSaveTextDocument(analyzeDocument),
    vscode.workspace.onDidChangeTextDocument((event) => {
      analyzeDocument(event.document);
    }),
    vscode.window.onDidChangeActiveTextEditor((editor) => {
      if (editor) {
        analyzeDocument(editor.document);
      }
    }),
    vscode.languages.registerCodeActionsProvider(
      ["javascript", "typescript", "javascriptreact", "typescriptreact"],
      new SecurityCodeActionProvider(),
      {
        providedCodeActionKinds:
          SecurityCodeActionProvider.providedCodeActionKinds,
      }
    )
  );
}

export function deactivate() {}