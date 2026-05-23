import * as vscode from "vscode";

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of context.diagnostics) {
      const ruleCode = String(diagnostic.code ?? "");

      switch (ruleCode) {
        case "SESSION_RESAVE_TRUE":
          actions.push(this.fixResaveTrue(document, diagnostic));
          break;

        case "SESSION_SAVEUNINITIALIZED_TRUE":
          actions.push(this.fixSaveUninitializedTrue(document, diagnostic));
          break;

        case "SESSION_COOKIE_SAMESITE_MISSING":
          actions.push(this.addSameSiteFix(document, diagnostic));
          break;

        case "SESSION_SECRET_HARDCODED":
          actions.push(this.replaceHardcodedSecretFix(document, diagnostic));
          break;

        case "SESSION_SECRET_WEAK":
          actions.push(this.replaceWeakSecretFix(document, diagnostic));
          break;

        case "JSON_LIMIT_MISSING":
          actions.push(this.addJsonLimitFix(document, diagnostic));
          break;

        case "XPOWEREDBY_MISSING":
          actions.push(this.addDisableXPoweredByFix(document, diagnostic));
          break;

        case "HELMET_MISSING":
          actions.push(this.addHelmetFix(document, diagnostic));
          break;
      }
    }

    return actions.filter(Boolean);
  }

  private fixResaveTrue(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `Change resave to false`,
      vscode.CodeActionKind.QuickFix
    );
    action.diagnostics = [diagnostic];
    action.isPreferred = true;

    const text = document.getText();
    const match = /resave\s*:\s*true\b/m.exec(text);
    if (!match) return action;

    const start = document.positionAt(match.index);
    const end = document.positionAt(match.index + match[0].length);

    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, new vscode.Range(start, end), "resave: false");
    action.edit = edit;

    return action;
  }

  private fixSaveUninitializedTrue(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `Change saveUninitialized to false`,
      vscode.CodeActionKind.QuickFix
    );
    action.diagnostics = [diagnostic];
    action.isPreferred = true;

    const text = document.getText();
    const match = /saveUninitialized\s*:\s*true\b/m.exec(text);
    if (!match) return action;

    const start = document.positionAt(match.index);
    const end = document.positionAt(match.index + match[0].length);

    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      document.uri,
      new vscode.Range(start, end),
      "saveUninitialized: false"
    );
    action.edit = edit;

    return action;
  }

  private addSameSiteFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `Add cookie.sameSite: "lax"`,
      vscode.CodeActionKind.QuickFix
    );
    action.diagnostics = [diagnostic];

    const text = document.getText();
    const cookieMatch = /cookie\s*:\s*\{([\s\S]*?)\}/m.exec(text);

    if (!cookieMatch || cookieMatch.index === undefined) {
      return action;
    }

    if (/sameSite\s*:/.test(cookieMatch[0])) {
      return action;
    }

    const insertOffset = cookieMatch.index + cookieMatch[0].length - 1;
    const insertPos = document.positionAt(insertOffset);

    const edit = new vscode.WorkspaceEdit();
    edit.insert(document.uri, insertPos, `,\n      sameSite: "lax"`);
    action.edit = edit;

    return action;
  }

  private replaceHardcodedSecretFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `Replace hardcoded secret with process.env.SESSION_SECRET`,
      vscode.CodeActionKind.QuickFix
    );
    action.diagnostics = [diagnostic];
    action.isPreferred = true;

    const text = document.getText();
    const match = /secret\s*:\s*["'`][^"'`]+["'`]/m.exec(text);
    if (!match) return action;

    const start = document.positionAt(match.index);
    const end = document.positionAt(match.index + match[0].length);

    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      document.uri,
      new vscode.Range(start, end),
      "secret: process.env.SESSION_SECRET"
    );
    action.edit = edit;

    return action;
  }

  private replaceWeakSecretFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `Use process.env.SESSION_SECRET instead of a weak secret`,
      vscode.CodeActionKind.QuickFix
    );
    action.diagnostics = [diagnostic];

    const text = document.getText();
    const match = /secret\s*:\s*["'`][^"'`]+["'`]/m.exec(text);
    if (!match) return action;

    const start = document.positionAt(match.index);
    const end = document.positionAt(match.index + match[0].length);

    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      document.uri,
      new vscode.Range(start, end),
      "secret: process.env.SESSION_SECRET"
    );
    action.edit = edit;

    return action;
  }

  private addJsonLimitFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `Add limit: "100kb" to express.json()`,
      vscode.CodeActionKind.QuickFix
    );
    action.diagnostics = [diagnostic];
    action.isPreferred = true;

    const text = document.getText();
    const match = /express\.json\(\s*\)/m.exec(text);
    if (!match) return action;

    const start = document.positionAt(match.index);
    const end = document.positionAt(match.index + match[0].length);

    const edit = new vscode.WorkspaceEdit();
    edit.replace(
      document.uri,
      new vscode.Range(start, end),
      `express.json({ limit: "100kb" })`
    );
    action.edit = edit;

    return action;
  }

  private addDisableXPoweredByFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `Add app.disable("x-powered-by")`,
      vscode.CodeActionKind.QuickFix
    );
    action.diagnostics = [diagnostic];

    const text = document.getText();

    if (/app\.disable\(\s*["']x-powered-by["']\s*\)/.test(text)) {
      return action;
    }

    const insertPos = this.findAppInsertPosition(document);
    const edit = new vscode.WorkspaceEdit();
    edit.insert(document.uri, insertPos, `app.disable("x-powered-by");\n`);
    action.edit = edit;

    return action;
  }

  private addHelmetFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `Add Helmet middleware`,
      vscode.CodeActionKind.QuickFix
    );
    action.diagnostics = [diagnostic];

    const text = document.getText();
    const edit = new vscode.WorkspaceEdit();

    const hasHelmetImport =
      /import\s+helmet\s+from\s+["']helmet["']/m.test(text) ||
      /const\s+helmet\s*=\s*require\(\s*["']helmet["']\s*\)/m.test(text);

    if (!hasHelmetImport) {
      edit.insert(
        document.uri,
        new vscode.Position(0, 0),
        `import helmet from "helmet";\n`
      );
    }

    if (!/app\.use\(\s*helmet\s*\(\s*\)\s*\)/m.test(text)) {
      const insertPos = this.findAppInsertPosition(document);
      edit.insert(document.uri, insertPos, `app.use(helmet());\n`);
    }

    action.edit = edit;
    return action;
  }

  private findAppInsertPosition(document: vscode.TextDocument): vscode.Position {
    const text = document.getText();

    const appMatch =
      /const\s+app\s*=\s*express\(\s*\)\s*;?/m.exec(text) ||
      /let\s+app\s*=\s*express\(\s*\)\s*;?/m.exec(text) ||
      /var\s+app\s*=\s*express\(\s*\)\s*;?/m.exec(text);

    if (appMatch && appMatch.index !== undefined) {
      const endOffset = appMatch.index + appMatch[0].length;
      const pos = document.positionAt(endOffset);
      return new vscode.Position(pos.line + 1, 0);
    }

    return new vscode.Position(0, 0);
  }
}