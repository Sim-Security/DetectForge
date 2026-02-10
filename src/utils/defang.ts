/**
 * Defang/refang IOCs for safe handling.
 * Prevents accidental clicks or resolution of malicious indicators.
 */

/**
 * Defang an IOC for safe display/storage.
 * Examples:
 *   evil.com → evil[.]com
 *   http://evil.com → hxxp://evil[.]com
 *   192.168.1.1 → 192.168.1[.]1
 */
export function defang(ioc: string): string {
  let result = ioc;

  // Defang protocols
  result = result.replace(/^http/i, 'hxxp');
  result = result.replace(/^ftp/i, 'fxp');

  // Defang dots in domains/IPs (replace last dot, or all dots for IPs)
  if (isIPv4(ioc)) {
    // For IPs, defang the last octet separator
    const lastDot = result.lastIndexOf('.');
    if (lastDot !== -1) {
      result = result.substring(0, lastDot) + '[.]' + result.substring(lastDot + 1);
    }
  } else if (isDomain(ioc) || isUrl(ioc)) {
    // For domains/URLs, defang dots in the domain part
    result = result.replace(/\./g, '[.]');
  }

  // Defang @ in emails
  result = result.replace(/@/g, '[@]');

  return result;
}

/**
 * Refang a defanged IOC back to its original form.
 * Examples:
 *   evil[.]com → evil.com
 *   hxxp://evil[.]com → http://evil.com
 *   192.168.1[.]1 → 192.168.1.1
 */
export function refang(ioc: string): string {
  let result = ioc;

  // Refang protocols
  result = result.replace(/^hxxp/i, 'http');
  result = result.replace(/^fxp/i, 'ftp');

  // Refang dots
  result = result.replace(/\[\.\]/g, '.');
  result = result.replace(/\(\.\)/g, '.');
  result = result.replace(/\[dot\]/gi, '.');

  // Refang @
  result = result.replace(/\[@\]/g, '@');
  result = result.replace(/\[at\]/gi, '@');

  // Refang :// variants
  result = result.replace(/\[:\/\/\]/g, '://');

  return result;
}

// --- Helpers ---

function isIPv4(value: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value);
}

function isDomain(value: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value);
}

function isUrl(value: string): boolean {
  return /^(https?|ftp):\/\//i.test(value);
}
