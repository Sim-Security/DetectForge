/**
 * Simple structured logger for DetectForge.
 * Uses console with level filtering and optional structured output.
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const LEVEL_COLORS: Record<LogLevel, string> = {
  debug: '\x1b[90m',  // gray
  info: '\x1b[36m',   // cyan
  warn: '\x1b[33m',   // yellow
  error: '\x1b[31m',  // red
};

const RESET = '\x1b[0m';

let currentLevel: LogLevel = (process.env.LOG_LEVEL as LogLevel) || 'info';

export function setLogLevel(level: LogLevel): void {
  currentLevel = level;
}

function shouldLog(level: LogLevel): boolean {
  return LEVEL_PRIORITY[level] >= LEVEL_PRIORITY[currentLevel];
}

function formatMessage(level: LogLevel, component: string, message: string): string {
  const timestamp = new Date().toISOString().substring(11, 23);
  const color = LEVEL_COLORS[level];
  const levelTag = level.toUpperCase().padEnd(5);
  return `${RESET}${timestamp} ${color}${levelTag}${RESET} [${component}] ${message}`;
}

export function createLogger(component: string) {
  return {
    debug: (message: string, data?: unknown) => {
      if (shouldLog('debug')) {
        console.debug(formatMessage('debug', component, message), data ?? '');
      }
    },
    info: (message: string, data?: unknown) => {
      if (shouldLog('info')) {
        console.info(formatMessage('info', component, message), data ?? '');
      }
    },
    warn: (message: string, data?: unknown) => {
      if (shouldLog('warn')) {
        console.warn(formatMessage('warn', component, message), data ?? '');
      }
    },
    error: (message: string, data?: unknown) => {
      if (shouldLog('error')) {
        console.error(formatMessage('error', component, message), data ?? '');
      }
    },
  };
}
