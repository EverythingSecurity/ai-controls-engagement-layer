import { openDb, migrate } from '../src/db.ts';
import { seedRbac } from '../src/rbac/seed.ts';
const path = process.argv[2] ?? 'data/engagement.db';
const db = openDb(path);
console.log('migrations applied:', migrate(db));
console.log('rbac seeded:', seedRbac(db));
