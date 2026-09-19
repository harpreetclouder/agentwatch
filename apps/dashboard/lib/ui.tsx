import type { CSSProperties, ReactNode } from 'react';

export function Badge({
  label,
  tone = 'neutral',
}: {
  label: string;
  tone?: 'neutral' | 'ok' | 'warn' | 'block' | 'critical';
}) {
  const color =
    tone === 'ok'
      ? 'var(--ok)'
      : tone === 'warn'
        ? 'var(--warn)'
        : tone === 'block'
          ? 'var(--block)'
          : tone === 'critical'
            ? 'var(--critical)'
            : 'var(--muted)';

  return (
    <span
      style={{
        display: 'inline-block',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.72rem',
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
        color,
        border: `1px solid ${color}`,
        padding: '0.15rem 0.45rem',
        background: 'var(--surface)',
      }}
    >
      {label}
    </span>
  );
}

export function DecisionBadge({ decision }: { decision: string }) {
  const tone =
    decision === 'ALLOW'
      ? 'ok'
      : decision === 'WARN'
        ? 'warn'
        : decision === 'BLOCK'
          ? 'block'
          : decision === 'QUARANTINE'
            ? 'critical'
            : 'neutral';
  return <Badge label={decision} tone={tone} />;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const tone =
    severity === 'CRITICAL'
      ? 'critical'
      : severity === 'HIGH'
        ? 'block'
        : severity === 'MEDIUM'
          ? 'warn'
          : 'neutral';
  return <Badge label={severity} tone={tone} />;
}

export function StateBadge({ state }: { state: string }) {
  const tone =
    state === 'NORMAL' || state === 'ACTIVE'
      ? 'ok'
      : state === 'WARNING'
        ? 'warn'
        : state === 'RESTRICTED'
          ? 'block'
          : state === 'QUARANTINED'
            ? 'critical'
            : 'neutral';
  return <Badge label={state} tone={tone} />;
}

export function EmptyState({ children }: { children: ReactNode }) {
  return (
    <p
      style={{
        color: 'var(--muted)',
        fontSize: '0.95rem',
        lineHeight: 1.5,
        margin: '1.5rem 0',
      }}
    >
      {children}
    </p>
  );
}

export function PageHeader({
  title,
  subtitle,
}: {
  title: string;
  subtitle?: string;
}) {
  return (
    <header style={{ marginBottom: '1.75rem' }}>
      <h1
        style={{
          fontFamily: 'var(--font-display)',
          fontSize: '1.75rem',
          fontWeight: 600,
          letterSpacing: '-0.02em',
          margin: 0,
        }}
      >
        {title}
      </h1>
      {subtitle ? (
        <p style={{ margin: '0.4rem 0 0', color: 'var(--muted)', maxWidth: '42rem' }}>
          {subtitle}
        </p>
      ) : null}
    </header>
  );
}

export function DataTable({
  headers,
  rows,
}: {
  headers: string[];
  rows: ReactNode[][];
}) {
  const th: CSSProperties = {
    textAlign: 'left',
    fontFamily: 'var(--font-mono)',
    fontSize: '0.7rem',
    letterSpacing: '0.06em',
    textTransform: 'uppercase',
    color: 'var(--muted)',
    padding: '0.55rem 0.75rem',
    borderBottom: '1px solid var(--line)',
    fontWeight: 500,
  };
  const td: CSSProperties = {
    padding: '0.7rem 0.75rem',
    borderBottom: '1px solid var(--line-soft)',
    verticalAlign: 'top',
    fontSize: '0.9rem',
  };

  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            {headers.map((h) => (
              <th key={h} style={th}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i}>
              {row.map((cell, j) => (
                <td key={j} style={td}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return (
    <code
      style={{
        fontFamily: 'var(--font-mono)',
        fontSize: '0.85em',
        background: 'var(--surface-2)',
        padding: '0.1rem 0.35rem',
      }}
    >
      {children}
    </code>
  );
}
