const USERS: Record<string, string> = {
  admin: "correct horse battery staple",
};

export function login(user: string, password: string): boolean {
  if (!user || !password) return false;
  const expected = USERS[user];
  if (!expected) return false;
  return timingSafeEqual(expected, password);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
