-- Supabase RLS self-check, v1
--
-- Read-only. It reads Postgres's own settings (tables, policies, grants, functions) and
-- never selects a row of your data. Paste the whole file into Supabase -> SQL Editor -> Run.
--
-- What it can't tell you: whether User A can actually reach User B's data. A policy can
-- pass every check here and still be beaten in practice. Proving that takes real signed-in
-- users attacking a staging copy.
--
-- Paste the results into https://dfourmarvel.github.io/supabase-rls-selfcheck/ for a readable
-- report with an explanation of each check. Nothing is uploaded.

with
consts as (
  select
    -- A condition that only asks whether someone is signed in.
    '^\(*\s*((select\s+)?auth\.uid\(\)(\s+as\s+\w+)?\s*\)*\s*is\s+not\s+null'
      || '|((select\s+)?auth\.role\(\)(\s+as\s+\w+)?|\(*\s*auth\.jwt\(\)\s*->>\s*''role''(::text)?\s*\)*)\s*\)*\s*=\s*''authenticated''(::text)?)\s*\)*$'
      as signed_in_re,
    -- Columns that suggest a row belongs to, or identifies, a person.
    '(^|_)(user|owner|author|profile|customer|member|account|sender|recipient|receiver|creator|buyer|seller|client|patient|student|employee)_?id$|^(email|phone|created_by)$'
      as per_user_re,
    -- Columns that often grant power.
    '^(is_)?(role|roles|admin|superuser|staff|plan|tier|subscription|credits|balance|verified|approved|permissions|premium|pro)$'
      as power_re
),

exposed as (
  -- The schemas your API serves (Settings -> API -> Exposed schemas). Falls back to public.
  select distinct trim(s) as nspname
  from unnest(string_to_array(coalesce((
    select split_part(cfg, '=', 2)
    from pg_db_role_setting rs
    join pg_roles r on r.oid = rs.setrole
    cross join lateral unnest(rs.setconfig) cfg
    where r.rolname = 'authenticator' and cfg like 'pgrst.db_schemas=%'
    limit 1
  ), 'public'), ',')) s
  where trim(s) not in ('graphql_public', 'storage')
),

tbl as (
  select c.oid, n.nspname, c.relname, c.relrowsecurity as rls,
         format('%I.%I', n.nspname, c.relname) as obj,
         exists (
           select 1 from pg_attribute a
           where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
             and a.attname ~* (select per_user_re from consts)
         ) as per_user,
         -- An enabled BEFORE UPDATE row trigger, which may be guarding columns.
         exists (
           select 1 from pg_trigger tr
           where tr.tgrelid = c.oid and not tr.tgisinternal and tr.tgenabled in ('O', 'A')
             and tr.tgtype & 1 = 1 and tr.tgtype & 2 = 2 and tr.tgtype & 16 = 16
         ) as guarded,
         has_any_column_privilege('anon', c.oid, 'SELECT') as anon_read,
         has_any_column_privilege('anon', c.oid, 'INSERT, UPDATE') or has_table_privilege('anon', c.oid, 'DELETE') as anon_write,
         has_any_column_privilege('authenticated', c.oid, 'SELECT') as auth_read,
         has_any_column_privilege('authenticated', c.oid, 'INSERT, UPDATE') or has_table_privilege('authenticated', c.oid, 'DELETE') as auth_write
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  join exposed e on e.nspname = n.nspname
  where c.relkind in ('r', 'p')
),

pol0 as (
  select t.oid, t.obj, t.per_user, t.guarded, p.policyname, p.permissive, p.cmd,
         trim(coalesce(p.qual, '')) as q, trim(coalesce(p.with_check, '')) as w,
         trim(coalesce(p.qual, '')) ~* (select signed_in_re from consts) as q_signed_in,
         trim(coalesce(p.with_check, '')) ~* (select signed_in_re from consts) as w_signed_in,
         -- A policy only matters for a role that also holds the matching grant.
         p.roles && array['public', 'anon']::name[] and case p.cmd
           when 'DELETE' then has_table_privilege('anon', t.oid, 'DELETE')
           when 'ALL' then has_any_column_privilege('anon', t.oid, 'SELECT, INSERT, UPDATE')
                        or has_table_privilege('anon', t.oid, 'DELETE')
           else has_any_column_privilege('anon', t.oid, p.cmd) end as anon_grant,
         p.roles && array['public', 'authenticated']::name[] and case p.cmd
           when 'DELETE' then has_table_privilege('authenticated', t.oid, 'DELETE')
           when 'ALL' then has_any_column_privilege('authenticated', t.oid, 'SELECT, INSERT, UPDATE')
                        or has_table_privilege('authenticated', t.oid, 'DELETE')
           else has_any_column_privilege('authenticated', t.oid, p.cmd) end as auth_reach
  from pg_policies p
  join tbl t on t.nspname = p.schemaname and t.relname = p.tablename
  where t.rls
),

pol as (
  select *,
         q = 'true' or q_signed_in as q_open,
         w = 'true' or w_signed_in as w_open,
         -- anon holds the grant AND the condition lets anon through unconditionally.
         anon_grant and q = 'true' as anon_q_true,
         anon_grant and w = 'true' as anon_w_true
  from pol0
),

findings(severity, check_id, object, finding, fix) as (

  -- RLS-01: RLS switched off on a table the API can reach
  select
    case when anon_read or anon_write then 'critical' else 'high' end,
    'RLS-01', obj,
    'Row Level Security is OFF. '
      || case when anon_read or anon_write then 'Anyone with your public (anon) key' else 'Any signed-in user' end
      || ' can '
      || case
           when (anon_read or anon_write) then
             case when anon_read and anon_write then 'read and change' when anon_read then 'read' else 'change' end
           else
             case when auth_read and auth_write then 'read and change' when auth_read then 'read' else 'change' end
         end
      || ' every row through the API.',
    format('alter table %s enable row level security; -- then add a policy for each thing the app needs to do', obj)
  from tbl
  where not rls and (anon_read or anon_write or auth_read or auth_write)

  union all
  -- RLS-02: a read policy that lets everyone read everything
  select
    case when anon_q_true and per_user then 'high'
         when per_user then 'medium'
         else 'review' end,
    'RLS-02', obj || ' · ' || policyname,
    'Every row is readable by ' || case when anon_q_true then 'anyone with your public key' else 'every signed-in user' end
      || case when per_user then '. It has a column that identifies a person, so confirm every row and column is meant to be seen by them.'
              else '. Fine for public content like a catalogue; a leak for anything personal.' end,
    'Replace the condition with an ownership check, for example using (user_id = (select auth.uid())).'
  from pol
  where cmd in ('SELECT', 'ALL') and q_open and (anon_q_true or auth_reach)

  union all
  -- RLS-02: a write policy that checks nothing
  select
    case
      -- An UPDATE only reaches rows the caller's SELECT policy shows, and the new row is
      -- checked against SELECT too, so an unchecked edit is only a live hole when reads are open.
      when cmd = 'UPDATE' and not q_open
       and not exists (select 1 from pol r where r.oid = pol.oid and r.cmd in ('SELECT', 'ALL') and r.q_open)
        then 'review'
      else 'high' end,
    'RLS-02', obj || ' · ' || policyname,
    case
      when cmd = 'INSERT' then 'New rows are not checked, so a user can create rows in someone else''s name.'
      when w_open and not q_open
       and not exists (select 1 from pol r where r.oid = pol.oid and r.cmd in ('SELECT', 'ALL') and r.q_open)
        then 'Edited rows are not checked, so a user can hand a row to anyone who can also read it under your read policy. With owner-only reads that is no one; with shared or team reads it is a real hole.'
      when w_open and not q_open
        then 'Edited rows are not checked, and users can read rows they don''t own, so a user can hand a row to someone else or change who owns it.'
      else case when anon_q_true or anon_w_true then 'Anyone with your public key' else 'Any signed-in user' end
        || ' can ' || case cmd when 'ALL' then 'change or delete' when 'DELETE' then 'delete' else 'change' end || ' rows they can see.'
    end,
    case when cmd = 'INSERT' or (w_open and not q_open)
      then 'Replace the check with an ownership check, for example with check (user_id = (select auth.uid())).'
      else 'Replace the condition with an ownership check, for example using (user_id = (select auth.uid())).' end
  from pol
  where cmd in ('INSERT', 'UPDATE', 'DELETE', 'ALL')
    and (w_open or (q_open and cmd <> 'INSERT'))
    and (anon_q_true or anon_w_true or auth_reach)

  union all
  -- RLS-03: several permissive policies for the same action are OR'd together
  select 'review', 'RLS-03', min(obj) || ' · ' || lower(cmd),
    count(*) || ' policies allow ' || lower(cmd) || ' (' || string_agg(policyname, ', ' order by policyname)
      || '). Postgres combines them with OR, so the loosest one wins.',
    'Check each one on its own is no broader than you intend, or merge them into one policy.'
  from pol
  where permissive = 'PERMISSIVE' and cmd <> 'ALL' and (anon_grant or auth_reach)
  group by oid, cmd
  having count(*) > 1

  union all
  -- RLS-04: users can edit a column that looks like it grants power
  select
    case when t.guarded then 'review' else 'high' end,
    'RLS-04', t.obj,
    'Signed-in users can update ' || g.power_cols || ' on rows they can edit. If that column grants powers, a user can give them to themselves.'
      || case when t.guarded then ' A BEFORE UPDATE trigger exists; confirm it blocks this.' else '' end,
    format('revoke update on %s from authenticated;', t.obj)
      || case when g.safe_cols is not null then format(' grant update (%s) on %s to authenticated;', g.safe_cols, t.obj) else '' end
      || ' -- keep only the columns users should edit'
  from tbl t
  cross join lateral (
    select string_agg(a.attname, ', ' order by a.attname) filter (where a.attname ~* (select power_re from consts)) as power_cols,
           -- Suggested grant leaves out power columns, keys, and anything that names a person or owner.
           string_agg(quote_ident(a.attname), ', ' order by a.attnum) filter (
             where a.attname !~* (select power_re from consts)
               and a.attname !~* (select per_user_re from consts)
               and a.attname !~* '(^id$|_id$|^created_at$)'
               and not exists (select 1 from pg_index i where i.indrelid = t.oid and i.indisprimary and a.attnum = any(i.indkey))
           ) as safe_cols
    from pg_attribute a
    where a.attrelid = t.oid and a.attnum > 0 and not a.attisdropped
      and has_column_privilege('authenticated', t.oid, a.attname, 'UPDATE')
  ) g
  where t.rls and g.power_cols is not null
    and exists (select 1 from pol p where p.oid = t.oid and p.cmd in ('UPDATE', 'ALL') and p.auth_reach)

  union all
  -- RLS-06: an update policy shared by more than one party
  select case when guarded then 'review' else 'medium' end, 'RLS-06', obj || ' · ' || policyname,
    'More than one person can edit these rows. Check neither can change who the other party is (for example swap the vendor_id for someone else).'
      || case when guarded then ' A BEFORE UPDATE trigger exists; confirm it blocks this.' else '' end,
    'Leave the party columns out of the update grant, or block changes to them with a BEFORE UPDATE trigger. Repeating the same condition in with check does not stop the swap.'
  from pol
  where cmd in ('UPDATE', 'ALL') and auth_reach and q ~ '( OR |= ANY )' and not w_open

  union all
  -- RLS-07: policy trusts user metadata, which users can edit themselves
  select 'critical', 'RLS-07', obj || ' · ' || policyname,
    'This policy reads user metadata (user_metadata or raw_user_meta_data). Users can edit their own metadata from the browser, so they can pass this check.',
    'Store roles and permissions in app_metadata (only your server can set it) or in a table users cannot write.'
  from pol
  where (q || ' ' || w) ~* 'user_meta_?data' and (anon_grant or auth_reach)

  union all
  -- RLS-08: security definer functions callable from the browser
  select
    case when has_function_privilege('anon', p.oid, 'EXECUTE') then 'high' else 'review' end,
    'RLS-08', format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)),
    'Runs as its owner (' || pg_get_userbyid(p.proowner) || '), which on Supabase usually skips RLS, and '
      || case when has_function_privilege('anon', p.oid, 'EXECUTE') then 'anyone with your public key' else 'any signed-in user' end
      || ' can call it with rpc().',
    format('revoke execute on function %I.%I(%s) from public, anon; -- then grant it only to roles that need it, and check it filters by auth.uid() inside',
           n.nspname, p.proname, pg_get_function_identity_arguments(p.oid))
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  join exposed e on e.nspname = n.nspname
  where p.prokind = 'f' and p.prosecdef
    and pg_get_function_result(p.oid) <> 'trigger'
    and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')
    and (has_function_privilege('anon', p.oid, 'EXECUTE') or has_function_privilege('authenticated', p.oid, 'EXECUTE'))

  union all
  select 'medium', 'RLS-08', format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)),
    'Security definer function without a fixed search_path. Someone who can create objects in a schema it searches could make it run their code with its owner''s rights.',
    format('alter function %I.%I(%s) set search_path = ''''; -- then schema-qualify every name inside it', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid))
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  join exposed e on e.nspname = n.nspname
  where p.prokind = 'f' and p.prosecdef
    and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')
    and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) cfg where cfg like 'search_path=%')

  union all
  -- RLS-09: views that read tables with the view owner's rights
  select
    case when has_table_privilege('anon', c.oid, 'SELECT') then 'high' else 'medium' end,
    'RLS-09', format('%I.%I', n.nspname, c.relname),
    case c.relkind when 'm' then 'Materialized view' else 'View' end
      || ' readable by ' || case when has_table_privilege('anon', c.oid, 'SELECT') then 'anyone with your public key' else 'signed-in users' end
      || '. It reads its tables as its owner, so their RLS policies may not apply.',
    case c.relkind
      when 'm' then format('revoke select on %I.%I from anon, authenticated; -- materialized views cannot apply RLS', n.nspname, c.relname)
      else format('alter view %I.%I set (security_invoker = true);', n.nspname, c.relname) end
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  join exposed e on e.nspname = n.nspname
  where c.relkind in ('v', 'm')
    and not exists (select 1 from pg_depend d where d.objid = c.oid and d.deptype = 'e')
    and (has_table_privilege('anon', c.oid, 'SELECT') or has_table_privilege('authenticated', c.oid, 'SELECT'))
    and (c.relkind = 'm' or not exists (
      select 1 from unnest(coalesce(c.reloptions, '{}')) o where o ~* '^security_invoker=(true|on|yes|1)$'))

  union all
  -- RLS-11: storage
  select 'review', 'RLS-11', 'bucket ' || id,
    'Public bucket: anyone with a file''s URL can download it. Fine for avatars and product images, not for documents or private uploads.',
    'Make the bucket private and serve files with signed URLs, if anything in it is personal.'
  from storage.buckets
  where public

  union all
  select 'high', 'RLS-11', 'storage.objects · ' || policyname,
    'This storage policy doesn''t check who the user is, so any user can '
      || case cmd when 'ALL' then 'upload, overwrite or delete files' when 'INSERT' then 'upload files into any folder, including other people''s' when 'UPDATE' then 'overwrite other people''s files' when 'DELETE' then 'delete other people''s files' end
      || case when coalesce(qual, '') || coalesce(with_check, '') ~ 'bucket_id' then ' in that bucket.' else '.' end,
    'Add an ownership check, for example (storage.foldername(name))[1] = (select auth.uid())::text, or owner_id = (select auth.uid())::text.'
  from pg_policies
  where schemaname = 'storage' and tablename = 'objects'
    and cmd in ('INSERT', 'UPDATE', 'DELETE', 'ALL')
    -- Counts as an identity check only if it compares against the user's id.
    and coalesce(qual, '') || ' ' || coalesce(with_check, '') !~* '(auth\.uid\(\)|auth\.jwt\(\)\s*->>\s*''sub'')'
)

select severity, check_id, object, finding, fix
from (
  select *, case severity when 'critical' then 1 when 'high' then 2 when 'medium' then 3 when 'review' then 4 end as rank
  from findings
  union all
  select 'ok', '-', '-', 'No configuration problems found by this check.', '-', 5
  where not exists (select 1 from findings)
  union all
  select 'note', '-', '-',
    'Checked: ' || (select string_agg(nspname, ', ') from exposed) || ' plus storage. A clean result means the settings look right, not that User A can''t reach User B''s data.',
    'That takes testing with real accounts against a staging copy.', 6
) r
order by rank, check_id, object;
