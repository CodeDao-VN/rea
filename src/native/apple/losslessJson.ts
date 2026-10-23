/** A JSON value that keeps integer literals as decimal text. */
export type LosslessJson =
  | { readonly kind: "null" }
  | { readonly kind: "boolean"; readonly value: boolean }
  | { readonly kind: "string"; readonly value: string }
  | { readonly kind: "integer"; readonly decimal: string }
  | { readonly kind: "number"; readonly recorded: string }
  | { readonly kind: "array"; readonly items: readonly LosslessJson[] }
  | {
      readonly kind: "object";
      readonly members: Readonly<Record<string, LosslessJson>>;
    };

/** JSON text could not be parsed as a single complete value. */
export class LosslessJsonFailure extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LosslessJsonFailure";
  }
}

const isDigit = (code: number): boolean => code >= 48 && code <= 57;

/** Parse one JSON value, preserving integer literals that exceed IEEE-754 range. */
export const parseLosslessJson = (
  text: string,
  start = 0,
): { readonly value: LosslessJson; readonly end: number } => {
  const parser = new Parser(text, start);
  const value = parser.parseValue();
  return { value, end: parser.position };
};

export const objectMember = (
  value: LosslessJson,
  key: string,
): LosslessJson | undefined =>
  value.kind === "object" ? value.members[key] : undefined;

export const asString = (value: LosslessJson | undefined): string | null =>
  value?.kind === "string" ? value.value : null;

export const asBoolean = (value: LosslessJson | undefined): boolean | null =>
  value?.kind === "boolean" ? value.value : null;

export const asInteger = (value: LosslessJson | undefined): string | null =>
  value?.kind === "integer" ? value.decimal : null;

export const asObject = (
  value: LosslessJson | undefined,
): Readonly<Record<string, LosslessJson>> | null =>
  value?.kind === "object" ? value.members : null;

export const asArray = (
  value: LosslessJson | undefined,
): readonly LosslessJson[] | null =>
  value?.kind === "array" ? value.items : null;

export const objectKeys = (
  members: Readonly<Record<string, LosslessJson>>,
): readonly string[] => Object.keys(members);

class Parser {
  position: number;

  constructor(
    readonly text: string,
    start: number,
  ) {
    this.position = start;
  }

  parseValue(): LosslessJson {
    this.skipWhitespace();
    const ch = this.text[this.position];
    if (ch === undefined)
      throw new LosslessJsonFailure("Unexpected end of JSON input");
    if (ch === "{") return this.parseObject();
    if (ch === "[") return this.parseArray();
    if (ch === '"') return { kind: "string", value: this.parseString() };
    if (ch === "t")
      return this.literal("true", { kind: "boolean", value: true });
    if (ch === "f")
      return this.literal("false", { kind: "boolean", value: false });
    if (ch === "n") return this.literal("null", { kind: "null" });
    if (ch === "-" || isDigit(ch.charCodeAt(0))) return this.parseNumber();
    throw new LosslessJsonFailure(
      `Unexpected ${JSON.stringify(ch)} at JSON offset ${String(this.position)}`,
    );
  }

  private parseObject(): LosslessJson {
    this.position += 1;
    const members: Record<string, LosslessJson> = Object.create(null) as Record<
      string,
      LosslessJson
    >;
    this.skipWhitespace();
    if (this.text[this.position] === "}") {
      this.position += 1;
      return { kind: "object", members };
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.position] !== '"')
        throw new LosslessJsonFailure(
          `Expected a JSON object key at offset ${String(this.position)}`,
        );
      const key = this.parseString();
      if (Object.hasOwn(members, key))
        throw new LosslessJsonFailure(
          `Duplicate JSON object key ${JSON.stringify(key)}`,
        );
      this.skipWhitespace();
      this.expect(":");
      members[key] = this.parseValue();
      this.skipWhitespace();
      const next = this.text[this.position];
      if (next === "}") {
        this.position += 1;
        return { kind: "object", members };
      }
      if (next !== ",")
        throw new LosslessJsonFailure(
          `Expected ',' or '}' in JSON object at offset ${String(this.position)}`,
        );
      this.position += 1;
    }
  }

  private parseArray(): LosslessJson {
    this.position += 1;
    const items: LosslessJson[] = [];
    this.skipWhitespace();
    if (this.text[this.position] === "]") {
      this.position += 1;
      return { kind: "array", items };
    }
    for (;;) {
      items.push(this.parseValue());
      this.skipWhitespace();
      const next = this.text[this.position];
      if (next === "]") {
        this.position += 1;
        return { kind: "array", items };
      }
      if (next !== ",")
        throw new LosslessJsonFailure(
          `Expected ',' or ']' in JSON array at offset ${String(this.position)}`,
        );
      this.position += 1;
    }
  }

  private parseString(): string {
    this.position += 1;
    let result = "";
    while (this.position < this.text.length) {
      const ch = this.text[this.position]!;
      if (ch === '"') {
        this.position += 1;
        return result;
      }
      if (ch === "\\") {
        this.position += 1;
        result += this.escape();
        continue;
      }
      if (ch.charCodeAt(0) < 0x20)
        throw new LosslessJsonFailure(
          "Unescaped control character in JSON string",
        );
      result += ch;
      this.position += 1;
    }
    throw new LosslessJsonFailure("Unterminated JSON string");
  }

  private escape(): string {
    const ch = this.text[this.position];
    this.position += 1;
    switch (ch) {
      case '"':
      case "\\":
      case "/":
        return ch;
      case "b":
        return "\b";
      case "f":
        return "\f";
      case "n":
        return "\n";
      case "r":
        return "\r";
      case "t":
        return "\t";
      case "u": {
        const hex = this.text.slice(this.position, this.position + 4);
        if (!/^[0-9a-fA-F]{4}$/u.test(hex))
          throw new LosslessJsonFailure("Invalid JSON Unicode escape");
        this.position += 4;
        return String.fromCharCode(Number.parseInt(hex, 16));
      }
      default:
        throw new LosslessJsonFailure("Invalid JSON string escape");
    }
  }

  private parseNumber(): LosslessJson {
    const start = this.position;
    if (this.text[this.position] === "-") this.position += 1;
    if (this.text[this.position] === "0") this.position += 1;
    else {
      if (!isDigit(this.text.charCodeAt(this.position)))
        throw new LosslessJsonFailure("Invalid JSON number");
      while (isDigit(this.text.charCodeAt(this.position))) this.position += 1;
    }
    let fractional = false;
    if (this.text[this.position] === ".") {
      fractional = true;
      this.position += 1;
      if (!isDigit(this.text.charCodeAt(this.position)))
        throw new LosslessJsonFailure("Invalid JSON number fraction");
      while (isDigit(this.text.charCodeAt(this.position))) this.position += 1;
    }
    if (this.text[this.position] === "e" || this.text[this.position] === "E") {
      fractional = true;
      this.position += 1;
      if (this.text[this.position] === "+" || this.text[this.position] === "-")
        this.position += 1;
      if (!isDigit(this.text.charCodeAt(this.position)))
        throw new LosslessJsonFailure("Invalid JSON number exponent");
      while (isDigit(this.text.charCodeAt(this.position))) this.position += 1;
    }
    const recorded = this.text.slice(start, this.position);
    return fractional
      ? { kind: "number", recorded }
      : { kind: "integer", decimal: recorded };
  }

  private literal<T extends LosslessJson>(token: string, value: T): T {
    if (this.text.slice(this.position, this.position + token.length) !== token)
      throw new LosslessJsonFailure(`Expected ${token} in JSON`);
    this.position += token.length;
    return value;
  }

  private expect(token: string): void {
    if (this.text.slice(this.position, this.position + token.length) !== token)
      throw new LosslessJsonFailure(
        `Expected ${JSON.stringify(token)} at JSON offset ${String(this.position)}`,
      );
    this.position += token.length;
  }

  private skipWhitespace(): void {
    while (this.position < this.text.length) {
      const ch = this.text[this.position];
      if (ch !== " " && ch !== "\t" && ch !== "\n" && ch !== "\r") return;
      this.position += 1;
    }
  }
}
