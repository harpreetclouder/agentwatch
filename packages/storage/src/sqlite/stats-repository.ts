import type { SessionStats } from '../types.js';
import type {
  EventRepository,
  SecurityDecisionRepository,
  StatsRepository,
} from '../repositories.js';

export class SqliteStatsRepository implements StatsRepository {
  constructor(
    private readonly events: EventRepository,
    private readonly decisions: SecurityDecisionRepository,
  ) {}

  async getSessionStats(sessionId: string): Promise<SessionStats> {
    const [events, counts] = await Promise.all([
      this.events.countBySession(sessionId),
      this.decisions.countBySession(sessionId),
    ]);

    return {
      sessionId,
      events,
      warnings: counts.warnings,
      blocks: counts.blocks,
      critical: counts.critical,
    };
  }
}
