import { timingSafeEqual } from "node:crypto";

const USERS: Record<string, string> = {
  demo: "correct horse battery staple",
};

export function login(user: string, password: string): boolean {
  if (!user || !password) return false;
  const expected = USERS[user];
  if (!expected) return false;
  const a = Buffer.from(password);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
