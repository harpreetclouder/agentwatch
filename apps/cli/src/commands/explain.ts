import { existsSync, readFileSync } from 'node:fs';
import { formatExplainReport, type SecurityReport } from '@jev/attack-engine';
import { printBanner } from '../ui.js';
import { lastReportPath } from './attack.js';

export function cmdExplain(_args: string[]): number {
  printBanner();

  const path = lastReportPath();
  if (!existsSync(path)) {
    console.log('No security report found.');
    console.log('');
    console.log('Run `jev attack` first to generate a report.');
    console.log('');
    return 1;
  }

  try {
    const report = JSON.parse(readFileSync(path, 'utf8')) as SecurityReport;
    console.log(formatExplainReport(report));
    return 0;
  } catch {
    console.error('Failed to read last security report.');
    return 1;
  }
}
