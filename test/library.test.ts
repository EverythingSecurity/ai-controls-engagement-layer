import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDb, migrate } from '../src/db.ts';
import { importLibrary } from '../src/library.ts';

test('library import: all 557 master-list controls, 18 frameworks, every control flagged for review', () => {
  const db = openDb(); migrate(db);
  const s = importLibrary(db, 'AI_Governance_Master_Checklist.json');
  assert.equal(s.controls, 557); assert.equal(s.frameworks, 18);
  assert.equal((db.prepare('SELECT count(*) n FROM control WHERE metadata_status != ?').get('needs_content_review') as any).n, 0);
  assert.equal((db.prepare('SELECT count(*) n FROM control WHERE applies_if IS NOT NULL OR owner_function IS NOT NULL OR depth_tier IS NOT NULL').get() as any).n, 0, 'nothing invented');
  assert.equal(s.gaps.applies_if, 557); assert.equal(s.gaps.question_templates, 557);
  assert.equal((db.prepare('SELECT count(DISTINCT id) n FROM control').get() as any).n, 557);
  assert.throws(() => importLibrary(db, 'AI_Governance_Master_Checklist.json'), /already imported/);
});
