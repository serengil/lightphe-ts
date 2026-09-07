/**
 * Jest ships test results between workers as JSON, which cannot represent a
 * `bigint`. Without this, a failing assertion on any of the values this library
 * deals in crashes the reporter instead of printing a diff.
 */
(BigInt.prototype as unknown as { toJSON(): string }).toJSON = function (
  this: bigint
): string {
  return `${this.toString()}n`;
};

export {};
