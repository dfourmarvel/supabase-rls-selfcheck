// Plain-English background for each check. The query says what it found; this says why it matters.
export const CHECKS = {
  "RLS-01": {
    title: "Row Level Security is off",
    why: "The dashboard's Table Editor switches RLS on for you. Tables created with SQL, migrations or an ORM, which is what AI coding tools write, can easily end up with it off. With RLS off, the public key in your frontend is enough to reach the whole table.",
  },
  "RLS-02": {
    title: "A policy that checks nothing",
    why: "using (true), with check (true), or a condition that only asks whether someone is signed in, all let every user through. Anyone can sign up, so \"signed in\" is not a permission. The fix is a condition tied to the row, usually its owner.",
  },
  "RLS-03": {
    title: "Several policies for the same action",
    why: "Postgres combines permissive policies with OR. If one policy says \"owners read their own rows\" and another says \"members read everything\", everyone gets the looser one. This is often intended, like public listings next to private drafts, so it is marked for review.",
  },
  "RLS-04": {
    title: "Users can edit a column that grants power",
    why: "A policy that lets users update their own row usually lets them update every column in it, including role, plan or credits. A correct-looking policy can still hand out admin. RLS decides which rows, not which columns; column grants or a trigger decide the columns.",
  },
  "RLS-06": {
    title: "Rows shared by two people",
    why: "When a row belongs to two parties (a client and a vendor, a sender and a receiver), a policy like auth.uid() in (client_id, vendor_id) is still true after one party swaps the other out. Repeating the same condition in with check does not help, because it stays true too.",
  },
  "RLS-07": {
    title: "A policy that trusts user_metadata",
    why: "Signed-in users can change their own user_metadata (stored as raw_user_meta_data in auth.users) with one call from the browser. A policy that reads a role or permission from it can be passed by anyone who sets that value on themselves.",
  },
  "RLS-08": {
    title: "Functions that skip RLS",
    why: "A security definer function runs with its owner's rights. On Supabase the owner is usually a role that bypasses RLS, so your policies don't apply inside it. New functions in Postgres can be run by everyone unless you revoke that, and Supabase exposes them through rpc(). A missing auth check inside one is a direct way around your policies.",
  },
  "RLS-09": {
    title: "Views that skip RLS",
    why: "By default a view reads its tables with the view owner's rights, which on Supabase is usually a role that bypasses RLS. Your table policies can be perfect and the view can still return every row. Setting security_invoker makes the view use the caller's rights instead.",
  },
  "RLS-11": {
    title: "Storage buckets and policies",
    why: "Public buckets serve any file to anyone who has or guesses its URL. Storage policies are RLS policies on storage.objects, so a rule that only checks the bucket lets any user upload, overwrite or delete other people's files in it.",
  },
};

// A realistic result from a project with a few common mistakes, for the preview and the sample button.
export const SAMPLE = [
  { severity: "critical", check_id: "RLS-01", object: "public.invoices", finding: "Row Level Security is OFF. Anyone with your public (anon) key can read and change every row through the API.", fix: "alter table public.invoices enable row level security; -- then add a policy for each thing the app needs to do" },
  { severity: "high", check_id: "RLS-04", object: "public.profiles", finding: "Signed-in users can update plan, role on rows they can edit. If that column grants powers, a user can give them to themselves.", fix: "revoke update on public.profiles from authenticated; grant update (full_name, avatar_url) on public.profiles to authenticated; -- keep only the columns users should edit" },
  { severity: "high", check_id: "RLS-08", object: "public.get_order(order_id uuid)", finding: "Runs as its owner (postgres), which on Supabase usually skips RLS, and anyone with your public key can call it with rpc().", fix: "revoke execute on function public.get_order(order_id uuid) from public, anon; -- then grant it only to roles that need it, and check it filters by auth.uid() inside" },
  { severity: "medium", check_id: "RLS-02", object: "public.messages · Enable read access for authenticated users", finding: "Every row is readable by every signed-in user. It has a column that identifies a person, so confirm every row and column is meant to be seen by them.", fix: "Replace the condition with an ownership check, for example using (user_id = (select auth.uid()))." },
  { severity: "review", check_id: "RLS-11", object: "bucket uploads", finding: "Public bucket: anyone with a file's URL can download it. Fine for avatars and product images, not for documents or private uploads.", fix: "Make the bucket private and serve files with signed URLs, if anything in it is personal." },
  { severity: "note", check_id: "-", object: "-", finding: "Checked: public plus storage. A clean result means the settings look right, not that User A can't reach User B's data.", fix: "That takes testing with real accounts against a staging copy." },
];
