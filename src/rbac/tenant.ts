import type { Db } from '../db.ts';
import type { Ctx } from './engine.ts';

/** Tables that carry client_id. Phase 2+ tables must be registered here so every query is tenant-scoped. */
export const CLIENT_OWNED_TABLES = new Set(['department']);

/** Client ids the caller may touch at all (the default query filter, A8). Empty = none. */
export function visibleClientIds(db: Db, ctx: Ctx): string[] {
  const { user } = ctx;
  const now = (ctx.now ?? new Date()).toISOString();
  const active = ctx.assignments.filter((a) => (!a.valid_from || a.valid_from <= now) && (!a.valid_to || a.valid_to > now));
  if (!active.length) return [];
  if (user.org_type === 'client') return [user.org_id!];
  if (user.org_type === 'principal') {
    const ids = new Set<string>();
    for (const a of active) {
      if (a.role === 'principal_admin')
        (db.prepare('SELECT id FROM client WHERE principal_id = ?').all(user.org_id) as any[]).forEach((r) => ids.add(r.id));
      else if (a.role !== 'principal_content_manager') a.client_ids.forEach((c) => ids.add(c));
    }
    return [...ids];
  }
  return []; // platform tier: no client content by default
}

/** The ONLY sanctioned way to list client-owned rows: always filtered by client_id. */
export function scopedList(db: Db, ctx: Ctx, table: string): any[] {
  if (!CLIENT_OWNED_TABLES.has(table)) throw new Error(`${table} is not a registered client-owned table`);
  const ids = visibleClientIds(db, ctx);
  if (!ids.length) return [];
  return db.prepare(`SELECT * FROM ${table} WHERE client_id IN (${ids.map(() => '?').join(',')})`).all(...ids);
}
