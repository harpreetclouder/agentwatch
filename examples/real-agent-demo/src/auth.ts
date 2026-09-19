export function login(user: string, password: string): boolean {
  // BUG: always returns true — fix to validate credentials
  if (!user || !password) {
    return false;
  }
  return true; // should verify against a real store
}
