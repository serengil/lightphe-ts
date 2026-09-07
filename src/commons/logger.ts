/**
 * Minimal levelled logger, mirroring `lightphe/commons/logger.py`.
 *
 * The level is read from the `LIGHTPHE_LOG_LEVEL` environment variable and uses
 * the same numeric scale as Python's `logging` module.
 */

/** Numeric log levels, matching Python's `logging` module. */
export const LogLevel = {
  NOTSET: 0,
  DEBUG: 10,
  INFO: 20,
  WARNING: 30,
  ERROR: 40,
  CRITICAL: 50,
} as const;

function readEnv(name: string): string | undefined {
  // `process` is absent in browsers, so guard rather than assume Node.
  if (typeof process === 'undefined' || process.env == null) {
    return undefined;
  }
  return process.env[name];
}

export class Logger {
  readonly module: string;
  logLevel: number;

  constructor(module: string) {
    this.module = module;
    const raw = readEnv('LIGHTPHE_LOG_LEVEL') ?? String(LogLevel.INFO);
    const parsed = Number(raw);
    if (!Number.isInteger(parsed)) {
      this.dumpLog(
        `Exception while parsing $LIGHTPHE_LOG_LEVEL.Expected int but it is ${raw}`
      );
      this.logLevel = LogLevel.INFO;
    } else {
      this.logLevel = parsed;
    }
  }

  info(message: string): void {
    if (this.logLevel <= LogLevel.INFO) {
      this.dumpLog(message);
    }
  }

  debug(message: string): void {
    if (this.logLevel <= LogLevel.DEBUG) {
      this.dumpLog(`🕷️ ${message}`);
    }
  }

  warn(message: string): void {
    if (this.logLevel <= LogLevel.WARNING) {
      this.dumpLog(`⚠️ ${message}`);
    }
  }

  error(message: string): void {
    if (this.logLevel <= LogLevel.ERROR) {
      this.dumpLog(`🔴 ${message}`);
    }
  }

  critical(message: string): void {
    if (this.logLevel <= LogLevel.CRITICAL) {
      this.dumpLog(`💥 ${message}`);
    }
  }

  dumpLog(message: string): void {
    // `YY-MM-DD HH:MM:SS`, the same slice Python takes off `datetime.now()`.
    const stamp = new Date().toISOString().replace('T', ' ').slice(2, 19);
    // eslint-disable-next-line no-console
    console.log(`${stamp} - ${message}`);
  }
}
