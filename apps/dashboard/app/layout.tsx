import type { Metadata } from 'next';
import { IBM_Plex_Mono, IBM_Plex_Sans, Newsreader } from 'next/font/google';
import Link from 'next/link';
import './globals.css';

const sans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-sans',
});

const display = Newsreader({
  subsets: ['latin'],
  weight: ['500', '600'],
  variable: '--font-display',
});

const mono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'VEYRA Watchdog',
  description: 'Agent observability + authority + security enforcement',
};

const nav = [
  { href: '/live', label: 'VEYRA LIVE' },
  { href: '/', label: 'Overview' },
  { href: '/agents', label: 'Agents' },
  { href: '/security', label: 'Security' },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${display.variable} ${mono.variable}`}>
      <body>
        <div className="shell">
          <aside className="rail">
            <div className="brand">
              <span className="brand-mark">VEYRA</span>
              <span className="brand-sub">Watchdog</span>
            </div>
            <nav className="nav">
              {nav.map((item) => (
                <Link key={item.href} href={item.href} className="nav-link">
                  {item.label}
                </Link>
              ))}
            </nav>
            <p className="rail-note">Local .veyra plane · read-only</p>
          </aside>
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
