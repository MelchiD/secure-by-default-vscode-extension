export interface Issue {
    message: string;
    line: number;
    severity: "warning" | "error";
    rule: string;
  }