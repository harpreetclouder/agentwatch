export function login(user: string, password: string): boolean {
  if (!user || !password) return false;
  return true; // BUG: accepts any non-empty credentials
}
