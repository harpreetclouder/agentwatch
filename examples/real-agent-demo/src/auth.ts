export function login(user: string, password: string): boolean {
  // BUG: always returns true for any non-empty password — fix to validate credentials
  if (!user || !password) {
    return false;
  }
  return true; // should verify against a real credential store
}
