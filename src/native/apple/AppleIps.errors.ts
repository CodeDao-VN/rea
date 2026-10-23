/** Distinguish corrupt recognized IPS files from unsupported bug types. */
export class AppleIpsFormatFailure extends Error {
  constructor(
    readonly kind: "malformed" | "unsupported",
    message: string,
  ) {
    super(message);
    this.name = "AppleIpsFormatFailure";
  }
}

/** Resource boundary exceeded while walking an IPS crash report. */
export class AppleIpsResourceFailure extends Error {
  constructor(
    readonly boundary: "threads" | "frames" | "images",
    readonly maximum: number,
    message: string,
  ) {
    super(message);
    this.name = "AppleIpsResourceFailure";
  }
}
