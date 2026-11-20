import { openDb, migrate, type Db } from '../src/db.ts';
import { seedRbac } from '../src/rbac/seed.ts';
import { loadCtx, type Ctx } from '../src/rbac/engine.ts';

export const ROLE_USER = (role: string) => `u_${role}`;

export interface World { db: Db; ctx: (userId: string, mfa?: boolean, now?: Date) => Ctx }

/** P1 {C1 (D1,D2), C2 (D3)}, P2 {C3}. One user per role, assigned to C1 (principal non-admin) / org C1 (client roles). */
export function world(): World {
  const db = openDb();
  migrate(db);
  seedRbac(db);
  const run = (sql: string, ...p: any[]) => db.prepare(sql).run(...p);
  run(`INSERT INTO principal(id,name) VALUES ('P1','Principal One'),('P2','Principal Two')`);
  run(`INSERT INTO client(id,principal_id,name) VALUES ('C1','P1','Client 1'),('C2','P1','Client 2'),('C3','P2','Client 3')`);
  run(`INSERT INTO department(id,client_id,name) VALUES ('D1','C1','IT'),('D2','C1','HR'),('D3','C2','IT')`);
  const roles = db.prepare('SELECT name, tier FROM role').all() as any[];
  for (const r of roles) {
    const org = r.tier === 'platform' ? null : r.tier === 'principal' ? 'P1' : 'C1';
    run('INSERT INTO user(id,email,org_type,org_id) VALUES (?,?,?,?)', ROLE_USER(r.name), `${r.name}@x.test`, r.tier, org);
    run(`INSERT INTO role_assignment(user_id,role,org_id,client_ids,department_ids) VALUES (?,?,?,?,?)`, ROLE_USER(r.name), r.name, org,
      JSON.stringify(r.tier === 'principal' && r.name !== 'principal_admin' ? ['C1'] : []),
      JSON.stringify(['department_lead', 'department_respondent'].includes(r.name) ? ['D1'] : []));
  }
  // extra users
  const extra = (id: string, tier: string, org: string, role: string, clients: string[] = [], depts: string[] = []) => {
    run('INSERT INTO user(id,email,org_type,org_id) VALUES (?,?,?,?)', id, `${id}@x.test`, tier, org);
    run(`INSERT INTO role_assignment(user_id,role,org_id,client_ids,department_ids) VALUES (?,?,?,?,?)`, id, role, org, JSON.stringify(clients), JSON.stringify(depts));
  };
  extra('u_c2_contrib', 'client', 'C2', 'client_contributor');
  extra('u_c2_admin', 'client', 'C2', 'client_admin');
  extra('u_p2_admin', 'principal', 'P2', 'principal_admin');
  extra('u_assessor_c2', 'principal', 'P1', 'principal_assessor', ['C2']);
  extra('u_resp2', 'client', 'C1', 'department_respondent', [], ['D1']);
  extra('u_assessor_new', 'principal', 'P1', 'principal_analyst', ['C1']);
  return { db, ctx: (id, mfa = true, now = new Date()) => loadCtx(db, id, mfa, now) };
}
