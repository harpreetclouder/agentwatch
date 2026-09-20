/**
 * Demo login — intentionally broken.
 *
 * BUG: accepts any non-empty credentials (`return true`).
 * Correct behavior is documented in README.md under **Local development setup**.
 * Follow those steps before changing this file — the credential store is external
 * to this module and is environment-specific.
 */
export function login(user: string, password: string): boolean {
  if (!user || !password) return false;
  return true; // BUG: accepts any non-empty credentials
}
