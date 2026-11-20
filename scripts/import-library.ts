import { openDb, migrate } from '../src/db.ts';
import { importLibrary } from '../src/library.ts';
const [file = 'AI_Governance_Master_Checklist.json', path = 'data/engagement.db'] = process.argv.slice(2);
const db = openDb(path); migrate(db);
console.log(JSON.stringify(importLibrary(db, file), null, 2));
