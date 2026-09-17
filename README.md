# Supabase RLS self-check

A free, read-only check of a Supabase project's Row Level Security setup. One SQL query, run in your own SQL Editor, lists configuration mistakes with a plain-English explanation and a fix for each.

**Web page:** https://dfourmarvel.github.io/supabase-rls-selfcheck/ (paste the results there for a readable report; nothing is uploaded)

## Use it

1. Open your project in the Supabase dashboard, then **SQL Editor**.
2. Paste the contents of [`rls-selfcheck.sql`](rls-selfcheck.sql) and press **Run**.
3. Read the results in the editor, or export them (JSON, CSV or markdown) and paste them into the web page.

The query only reads Postgres catalog information: table settings, policies, grants, functions, views and storage buckets. It never selects rows from your tables, and it changes nothing.

## What it flags

| Check | Looks for |
|---|---|
| RLS-01 | Tables with RLS off that the API can reach |
| RLS-02 | Policies that check nothing: `true`, or only "is signed in" |
| RLS-03 | Several permissive policies for one action (combined with OR) |
| RLS-04 | Users able to update columns like `role`, `plan` or `credits` |
| RLS-06 | Update policies on rows shared by two parties |
| RLS-07 | Policies that trust `user_metadata` |
| RLS-08 | Security definer functions callable through `rpc()`, or without a fixed `search_path` |
| RLS-09 | Views and materialized views that bypass RLS |
| RLS-11 | Public storage buckets and storage policies that check nothing |

Findings marked **review** are often intentional (a public catalogue, a public avatars bucket). Read the explanation before changing anything.

## What it can't tell you

A clean result means the settings look right. It does not prove that one user can't reach another user's data: a policy can be correct on paper and still be beaten, for example by an own-row update that rewrites a role column. Proving that takes testing with real accounts against a staging copy.

## Development

The page is static HTML, CSS and JavaScript with no build step. `parse.js` turns pasted results into findings and has tests:

```bash
npm test
```

Serve the folder with any static server (`python -m http.server`) to try the page locally; it fetches `rls-selfcheck.sql` from the same folder.

Not affiliated with Supabase. MIT licensed.
