/** Relative module syntax differs from an arbitrary dot-prefixed filename. */
export const isRelativeJavaScriptModuleSpecifier = (value: string): boolean =>
  value === "." ||
  value === ".." ||
  value.startsWith("./") ||
  value.startsWith("../");

/** File URLs treat raw backslashes as separators after relative module admission. */
export const normalizeRelativeModuleUrlSeparators = (value: string): string =>
  isRelativeJavaScriptModuleSpecifier(value)
    ? value.replaceAll("\\", "/")
    : value;
