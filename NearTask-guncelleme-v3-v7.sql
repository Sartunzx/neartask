-- NearTask: missing updates v3-v6 + v7 phone notifications. Paste all, then Run. Safe to re-run.
-- ==== PART 1: admin + ban flags, blocks ====
alter table public.profiles add column if not exists is_admin boolean not null default false;
alter table public.profiles add column if not exists banned boolean not null default false;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select is_admin from profiles where id = auth.uid()), false)
$$;

create or replace function public.is_banned() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select banned from profiles where id = auth.uid()), false)
$$;

create table if not exists public.blocks (
  blocker_id uuid not null references public.profiles(id) on delete cascade default auth.uid(),
  blocked_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id)
);
alter table public.blocks enable row level security;
drop policy if exists "blocks own" on public.blocks;
create policy "blocks own" on public.blocks for all using (blocker_id = auth.uid()) with check (blocker_id = auth.uid());

create or replace function public.blocked_between(a uuid, b uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from blocks where (blocker_id = a and blocked_id = b) or (blocker_id = b and blocked_id = a))
$$;

-- ==== PART 2: stricter insert rules (banned users and blocked pairs) ====
drop policy if exists "listings insert" on public.listings;
create policy "listings insert" on public.listings for insert with check (owner_id = auth.uid() and not public.is_banned());

drop policy if exists "applications insert" on public.applications;
create policy "applications insert" on public.applications for insert with check (
  not public.is_banned()
  and exists (select 1 from public.listings l where l.id = listing_id and l.status = 'open'
    and not public.blocked_between(l.owner_id, applicant_id)) and (
    (applicant_id = auth.uid() and status = 'pending' and not public.is_listing_owner(listing_id))
    or (status = 'invited' and public.is_listing_owner(listing_id) and applicant_id <> auth.uid())
  ));

create or replace function public.can_message(a uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from applications ap join listings li on li.id = ap.listing_id
    where ap.id = a and (ap.applicant_id = auth.uid() or li.owner_id = auth.uid())
      and not blocked_between(ap.applicant_id, li.owner_id)
  ) and not is_banned()
$$;

drop policy if exists "messages insert" on public.messages;
create policy "messages insert" on public.messages for insert with check (sender_id = auth.uid() and public.can_message(application_id));

-- ==== PART 3: report users, delete own account ====
alter table public.reports alter column listing_id drop not null;
alter table public.reports add column if not exists reported_user_id uuid references public.profiles(id) on delete cascade;
alter table public.reports add column if not exists status text not null default 'open';
do $$ begin
  alter table public.reports add constraint reports_target check (listing_id is not null or reported_user_id is not null);
exception when duplicate_object then null; end $$;

create or replace function public.delete_my_account() returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  delete from storage.objects where bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text;
  delete from auth.users where id = auth.uid();
end $$;
revoke execute on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;

-- ==== PART 4: admin tools ====
create or replace function public.admin_overview() returns json
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Not allowed'; end if;
  return json_build_object(
    'users', (select count(*) from profiles),
    'businesses', (select count(*) from profiles where account_type = 'business'),
    'seekers', (select count(*) from profiles where available and account_type = 'person'),
    'open_listings', (select count(*) from listings where status = 'open' and date >= current_date),
    'applications', (select count(*) from applications),
    'messages_7d', (select count(*) from messages where created_at > now() - interval '7 days'),
    'new_users_7d', (select count(*) from profiles where created_at > now() - interval '7 days'),
    'open_reports', (select count(*) from reports where status = 'open'));
end $$;

create or replace function public.admin_reports() returns json
language plpgsql stable security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Not allowed'; end if;
  return coalesce((select json_agg(r order by r.created_at desc) from (
    select rp.id, rp.reason, rp.status, rp.created_at, rp.listing_id, rp.reported_user_id,
      l.title as listing_title, l.status as listing_status, l.owner_id as listing_owner,
      rr.name as reporter_name, ru.name as reported_name, ru.banned as reported_banned
    from reports rp
    left join listings l on l.id = rp.listing_id
    left join profiles rr on rr.id = rp.reporter_id
    left join profiles ru on ru.id = coalesce(rp.reported_user_id, l.owner_id)
    order by rp.created_at desc limit 200) r), '[]'::json);
end $$;

-- ==== PART 5: admin actions ====
create or replace function public.admin_resolve_report(r uuid, s text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Not allowed'; end if;
  update reports set status = s where id = r;
end $$;

create or replace function public.admin_set_listing_status(l uuid, s text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Not allowed'; end if;
  update listings set status = s where id = l;
end $$;

create or replace function public.admin_set_verified(u uuid, v boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Not allowed'; end if;
  update profiles set verified = v where id = u;
end $$;

create or replace function public.admin_set_banned(u uuid, v boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'Not allowed'; end if;
  if u = auth.uid() then raise exception 'Cannot ban yourself'; end if;
  update profiles set banned = v where id = u;
  if v then update listings set status = 'closed' where owner_id = u and status = 'open'; end if;
end $$;

-- ==== PART 6: make the owner an admin (change the email if needed) ====
update public.profiles set is_admin = true
where id = (select id from auth.users where email = 'alitekincelik@gmail.com');

-- =====================================================================
-- v4: broader categories, smart request details, priced quotes,
--     stronger provider profiles (work photos + track record)
-- Safe to re-run. Run once in Supabase → SQL Editor → New query → Run.
-- =====================================================================

-- 1. Broad main categories
alter table public.listings drop constraint if exists listings_category_check;
alter table public.listings add constraint listings_category_check check (category in (
  'hospitality','retail','warehouse','cleaning','repairs','garden','moving','care',
  'family','lessons','beauty','events','tech','auto','other'));

-- 2. Smart request answers (e.g. {"type": "Deep clean", "size": "2 bedrooms"})
alter table public.listings add column if not exists details jsonb not null default '{}'::jsonb;
do $$ begin
  alter table public.listings add constraint listings_details_shape check (jsonb_typeof(details) = 'object' and length(details::text) <= 2000);
exception when duplicate_object then null; end $$;
grant update (kind, title, category, area, date, start_time, end_time, pay, description, requirements, photo_url, status, positions, lat, lng, details)
  on public.listings to authenticated;

-- 3. Priced quotes on applications / offers
alter table public.applications add column if not exists price numeric(10,2);
alter table public.applications add column if not exists price_unit text;
do $$ begin
  alter table public.applications add constraint applications_price check (price is null or (price >= 1 and price < 100000));
exception when duplicate_object then null; end $$;
alter table public.applications drop constraint if exists applications_price_unit;
alter table public.applications add constraint applications_price_unit check (
  (price is null and price_unit is null) or (price is not null and price_unit is not null and price_unit in ('total','hour')));

-- Only the status can change, except that the applicant may set a new price when (re)applying.
create or replace function public.check_application_update() returns trigger
language plpgsql security definer set search_path = public as $$
declare owner uuid;
begin
  if auth.uid() is null then return new; end if; -- dashboard / admin edits
  select owner_id into owner from listings where id = old.listing_id;
  if new.listing_id <> old.listing_id or new.applicant_id <> old.applicant_id or new.message <> old.message then
    raise exception 'Only the status can change';
  end if;
  if (new.price is distinct from old.price or new.price_unit is distinct from old.price_unit)
     and not (auth.uid() = old.applicant_id and new.status = 'pending') then
    raise exception 'Only the applicant can change their quote';
  end if;
  if auth.uid() = old.applicant_id then
    if old.status = 'invited' and new.status in ('accepted','declined') then return new; end if;
    if old.status in ('pending','declined','withdrawn') and new.status in ('withdrawn','pending') then return new; end if;
  end if;
  if auth.uid() = owner and old.status <> 'invited' and new.status in ('accepted','declined','pending') then return new; end if;
  if auth.uid() = owner and old.status = 'invited' and new.status = 'withdrawn' then return new; end if;
  raise exception 'Not allowed';
end $$;

-- Notifications mention the quoted price.
create or replace function public.on_application_notify() returns trigger
language plpgsql security definer set search_path = public as $$
declare l record; who text; q text;
begin
  select owner_id, title into l from listings where id = new.listing_id;
  q := case when new.price is null then ''
            else ' · £' || trim(to_char(new.price, 'FM99999.00')) || case when new.price_unit = 'hour' then '/hr' else '' end end;
  q := replace(q, '.00', '');
  if tg_op = 'INSERT' then
    if new.status = 'invited' then
      select name into who from profiles where id = l.owner_id;
      perform notify(new.applicant_id, 'invite', coalesce(nullif(who, ''), 'Someone') || ' invited you', l.title, '/chat/' || new.id);
    else
      select name into who from profiles where id = new.applicant_id;
      perform notify(l.owner_id, 'application',
        case when new.price is null then 'New applicant: ' else 'New quote: ' end || coalesce(nullif(who, ''), 'someone') || q,
        l.title, '/manage/' || new.listing_id);
    end if;
  elsif new.status <> old.status then
    if new.status in ('accepted','declined') and old.status = 'pending' then
      perform notify(new.applicant_id, new.status, initcap(new.status) || ': ' || l.title, '', '/chat/' || new.id);
    elsif old.status = 'invited' and new.status in ('accepted','declined') then
      select name into who from profiles where id = new.applicant_id;
      perform notify(l.owner_id, new.status, coalesce(nullif(who, ''), 'Worker') || ' ' || new.status || ' your invite', l.title, '/chat/' || new.id);
    end if;
  end if;
  return new;
end $$;

-- 4. Provider profiles: work photos and a public track record
alter table public.profiles add column if not exists portfolio text[] not null default '{}';
do $$ begin
  alter table public.profiles add constraint profiles_portfolio_max check (cardinality(portfolio) <= 8);
exception when duplicate_object then null; end $$;
grant update (name, postcode, bio, avatar_url, account_type, headline, skills, available, available_days, lat, lng, portfolio)
  on public.profiles to authenticated;

-- Jobs done, people hired and median reply time (minutes) over the last 120 days.
-- Returns totals only, never individual jobs or messages.
create or replace function public.profile_stats(u uuid) returns json
language sql stable security definer set search_path = public as $$
  with mine as (
    select a.id from applications a join listings l on l.id = a.listing_id
    where a.applicant_id = u or l.owner_id = u
  ), m as (
    select x.sender_id, x.created_at,
      lag(x.sender_id) over (partition by x.application_id order by x.created_at) as prev_sender,
      lag(x.created_at) over (partition by x.application_id order by x.created_at) as prev_at
    from messages x
    where x.application_id in (select id from mine) and x.created_at > now() - interval '120 days'
  )
  select json_build_object(
    'jobs_done', (select count(*) from applications a join listings l on l.id = a.listing_id
                  where a.applicant_id = u and a.status = 'accepted' and l.date <= current_date),
    'hires', (select count(*) from applications a join listings l on l.id = a.listing_id
              where l.owner_id = u and a.status = 'accepted'),
    'reply_minutes', (select round(percentile_cont(0.5) within group (order by extract(epoch from (m.created_at - m.prev_at)) / 60))::int
                      from m where m.sender_id = u and m.prev_sender is not null and m.prev_sender <> u))
$$;
grant execute on function public.profile_stats(uuid) to anon, authenticated;

-- =====================================================================
-- v5: automatic matching, price guide, job completion + NearTask Promise,
--     fixed-price services (packages)
-- Needs v4 first. Safe to re-run. Supabase → SQL Editor → New query → Run.
-- =====================================================================

-- ---------- 1. Automatic matching ----------
-- New requests are sent straight to nearby helpers who picked that category under "What I do".
alter table public.profiles add column if not exists match_alerts boolean not null default true;
grant update (name, postcode, bio, avatar_url, account_type, headline, skills, available, available_days, lat, lng, portfolio, match_alerts)
  on public.profiles to authenticated;

alter table public.listings add column if not exists notified int not null default 0;     -- how many helpers were told
alter table public.listings add column if not exists booked_package uuid;                  -- set when created by booking a package

create or replace function public.km_between(lat1 double precision, lng1 double precision, lat2 double precision, lng2 double precision)
returns double precision language sql immutable as $$
  select 6371 * 2 * asin(sqrt(power(sin(radians(lat2 - lat1) / 2), 2)
    + cos(radians(lat1)) * cos(radians(lat2)) * power(sin(radians(lng2 - lng1) / 2), 2)))
$$;

create or replace function public.on_listing_match() returns trigger
language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if new.status <> 'open' or new.booked_package is not null then return new; end if;
  with helpers as (
    select p.id from profiles p
    where p.id <> new.owner_id
      and p.match_alerts and not p.banned
      and new.category = any (p.skills)
      and (new.kind = 'service' or p.available)                -- shifts go to people looking for work
      and not blocked_between(p.id, new.owner_id)
      and (
        (p.lat is not null and new.lat is not null and km_between(p.lat, p.lng, new.lat, new.lng) <= 20)
        or ((p.lat is null or new.lat is null) and p.postcode <> '' and new.area ilike '%' || p.postcode || '%')
      )
      -- skip people who already got a saved-search alert for this listing
      and not exists (select 1 from notifications x where x.user_id = p.id and x.link = '/l/' || new.id)
    order by case when p.lat is not null and new.lat is not null then km_between(p.lat, p.lng, new.lat, new.lng) else 99 end
    limit 100
  ), sent as (
    insert into notifications (user_id, type, title, body, link)
    select h.id, 'match',
      case when new.kind = 'service' then 'New request near you: ' else 'New shift near you: ' end || new.title,
      left(new.area || ' · ' || new.pay, 140), '/l/' || new.id
    from helpers h
    returning 1
  )
  select count(*) into n from sent;
  update listings set notified = n where id = new.id;
  return new;
end $$;
drop trigger if exists listing_match on public.listings;
create trigger listing_match after insert on public.listings for each row execute function public.on_listing_match();

-- Saved-search alerts ignore private bookings.
create or replace function public.on_listing_alert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.booked_package is not null then return new; end if;
  insert into notifications (user_id, type, title, body, link)
  select distinct s.user_id, 'alert', 'New match: ' || new.title, new.area || ' - ' || new.pay, '/l/' || new.id
  from saved_searches s
  where s.user_id <> new.owner_id
    and (s.kind = 'all' or s.kind = new.kind)
    and (s.category = 'all' or s.category = new.category)
    and (s.q = '' or (new.title || ' ' || new.area || ' ' || new.description) ilike '%' || s.q || '%');
  return new;
end $$;

-- ---------- 2. Price guide ----------
-- Typical quotes for a category over the last year. Needs at least 3 quotes, otherwise returns null.
create or replace function public.price_guide(cat text) returns json
language sql stable security definer set search_path = public as $$
  with q as (
    select a.price, a.price_unit from applications a join listings l on l.id = a.listing_id
    where l.category = cat and a.price is not null and a.created_at > now() - interval '365 days'
  ), u as (
    select price_unit from q group by price_unit order by count(*) desc, price_unit limit 1
  ), s as (
    select q.price from q, u where q.price_unit = u.price_unit
  )
  select case when (select count(*) from s) < 3 then null else json_build_object(
    'n', (select count(*) from s),
    'unit', (select price_unit from u),
    'low', (select round(percentile_cont(0.25) within group (order by price)::numeric) from s),
    'mid', (select round(percentile_cont(0.5) within group (order by price)::numeric) from s),
    'high', (select round(percentile_cont(0.75) within group (order by price)::numeric) from s)) end
$$;
grant execute on function public.price_guide(text) to anon, authenticated;

-- ---------- 3. Job completion + NearTask Promise ----------
alter table public.applications add column if not exists completed_at timestamptz;

-- The person who posted marks an accepted job as done; both sides are asked for a review.
create or replace function public.complete_job(a uuid) returns void
language plpgsql security definer set search_path = public as $$
declare r record;
begin
  select ap.id, ap.applicant_id, ap.status, ap.completed_at, l.owner_id, l.title into r
  from applications ap join listings l on l.id = ap.listing_id where ap.id = a;
  if r.id is null or r.owner_id <> auth.uid() then raise exception 'Not allowed'; end if;
  if r.status <> 'accepted' then raise exception 'Only accepted jobs can be completed'; end if;
  if r.completed_at is not null then return; end if;
  update applications set completed_at = now() where id = a;
  perform notify(r.applicant_id, 'completed', 'Job done: ' || r.title, 'Leave a review to help others choose.', '/chat/' || a);
  perform notify(r.owner_id, 'completed', 'How did it go? ' || r.title, 'Leave a review to help others choose.', '/chat/' || a);
end $$;
revoke execute on function public.complete_job(uuid) from public, anon;
grant execute on function public.complete_job(uuid) to authenticated;

-- Report a problem with a job within 72 hours of it being completed (or of the job date).
create or replace function public.report_job_problem(a uuid, reason text) returns void
language plpgsql security definer set search_path = public as $$
declare r record; since timestamptz;
begin
  select ap.id, ap.applicant_id, ap.status, ap.completed_at, l.id as lid, l.owner_id, l.date into r
  from applications ap join listings l on l.id = ap.listing_id where ap.id = a;
  if r.id is null or auth.uid() not in (r.applicant_id, r.owner_id) then raise exception 'Not allowed'; end if;
  if r.status <> 'accepted' then raise exception 'Only accepted jobs'; end if;
  since := coalesce(r.completed_at, (r.date + 1)::timestamptz);
  if now() > since + interval '72 hours' then raise exception 'The 72-hour window has passed'; end if;
  if char_length(coalesce(reason, '')) not between 5 and 480 then raise exception 'Please describe the problem'; end if;
  insert into reports (reporter_id, listing_id, reported_user_id, reason)
  values (auth.uid(), r.lid, case when auth.uid() = r.owner_id then r.applicant_id else r.owner_id end, '[Job problem] ' || reason);
end $$;
revoke execute on function public.report_job_problem(uuid, text) from public, anon;
grant execute on function public.report_job_problem(uuid, text) to authenticated;

-- Track record counts completed jobs, and accepted jobs whose date has passed.
create or replace function public.profile_stats(u uuid) returns json
language sql stable security definer set search_path = public as $$
  with mine as (
    select a.id from applications a join listings l on l.id = a.listing_id
    where a.applicant_id = u or l.owner_id = u
  ), m as (
    select x.sender_id, x.created_at,
      lag(x.sender_id) over (partition by x.application_id order by x.created_at) as prev_sender,
      lag(x.created_at) over (partition by x.application_id order by x.created_at) as prev_at
    from messages x
    where x.application_id in (select id from mine) and x.created_at > now() - interval '120 days'
  )
  select json_build_object(
    'jobs_done', (select count(*) from applications a join listings l on l.id = a.listing_id
                  where a.applicant_id = u and a.status = 'accepted' and (a.completed_at is not null or l.date <= current_date)),
    'hires', (select count(*) from applications a join listings l on l.id = a.listing_id
              where l.owner_id = u and a.status = 'accepted'),
    'reply_minutes', (select round(percentile_cont(0.5) within group (order by extract(epoch from (m.created_at - m.prev_at)) / 60))::int
                      from m where m.sender_id = u and m.prev_sender is not null and m.prev_sender <> u))
$$;

-- Bookings get their own notification text.
create or replace function public.on_application_notify() returns trigger
language plpgsql security definer set search_path = public as $$
declare l record; who text; q text;
begin
  select owner_id, title, booked_package into l from listings where id = new.listing_id;
  q := case when new.price is null then ''
            else ' · £' || trim(to_char(new.price, 'FM99999.00')) || case when new.price_unit = 'hour' then '/hr' else '' end end;
  q := replace(q, '.00', '');
  if tg_op = 'INSERT' then
    if new.status = 'invited' and l.booked_package is not null then
      select name into who from profiles where id = l.owner_id;
      perform notify(new.applicant_id, 'booking', 'New booking' || q || ': ' || coalesce(nullif(who, ''), 'someone'), l.title, '/chat/' || new.id);
    elsif new.status = 'invited' then
      select name into who from profiles where id = l.owner_id;
      perform notify(new.applicant_id, 'invite', coalesce(nullif(who, ''), 'Someone') || ' invited you', l.title, '/chat/' || new.id);
    else
      select name into who from profiles where id = new.applicant_id;
      perform notify(l.owner_id, 'application',
        case when new.price is null then 'New applicant: ' else 'New quote: ' end || coalesce(nullif(who, ''), 'someone') || q,
        l.title, '/manage/' || new.listing_id);
    end if;
  elsif new.status <> old.status then
    if new.status in ('accepted','declined') and old.status = 'pending' then
      perform notify(new.applicant_id, new.status, initcap(new.status) || ': ' || l.title, '', '/chat/' || new.id);
    elsif old.status = 'invited' and new.status in ('accepted','declined') then
      select name into who from profiles where id = new.applicant_id;
      perform notify(l.owner_id, new.status, coalesce(nullif(who, ''), 'Worker') || ' ' || new.status || ' your invite', l.title, '/chat/' || new.id);
    end if;
  end if;
  return new;
end $$;

-- ---------- 4. Fixed-price services (packages) ----------
create table if not exists public.packages (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references public.profiles(id) on delete cascade default auth.uid(),
  category text not null check (category in ('hospitality','retail','warehouse','cleaning','repairs','garden','moving','care',
    'family','lessons','beauty','events','tech','auto','other')),
  title text not null check (char_length(title) between 3 and 80),
  description text not null default '' check (char_length(description) <= 800),
  price numeric(10,2) not null check (price >= 1 and price < 100000),
  price_unit text not null default 'total' check (price_unit in ('total','hour')),
  duration text not null default '' check (char_length(duration) <= 30),
  area text not null default '' check (char_length(area) <= 40),
  photo_url text,
  active boolean not null default true,
  lat double precision,
  lng double precision,
  created_at timestamptz not null default now()
);
create index if not exists packages_active on public.packages (category) where active;
alter table public.packages enable row level security;
drop policy if exists "packages read" on public.packages;
create policy "packages read" on public.packages for select using (active or owner_id = auth.uid());
drop policy if exists "packages insert" on public.packages;
create policy "packages insert" on public.packages for insert with check (owner_id = auth.uid() and not public.is_banned());
drop policy if exists "packages update" on public.packages;
create policy "packages update" on public.packages for update using (owner_id = auth.uid()) with check (owner_id = auth.uid());
drop policy if exists "packages delete" on public.packages;
create policy "packages delete" on public.packages for delete using (owner_id = auth.uid());
grant select on public.packages to anon, authenticated;
grant insert, update, delete on public.packages to authenticated;

-- Booking a package creates a private request and invites the provider at the package price.
-- Done in one step so the booking is consistent; the provider then accepts in the chat.
create or replace function public.book_package(pkg uuid, d date, t time, addr text, note text) returns uuid
language plpgsql security definer set search_path = public as $$
declare p record; lid uuid; aid uuid; msg text; payt text;
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  if is_banned() then raise exception 'Not allowed'; end if;
  select * into p from packages where id = pkg and active;
  if p.id is null then raise exception 'This service is no longer available'; end if;
  if p.owner_id = auth.uid() then raise exception 'You cannot book your own service'; end if;
  if blocked_between(p.owner_id, auth.uid()) then raise exception 'Not allowed'; end if;
  if d is null or d < current_date then raise exception 'Pick a date from today'; end if;
  payt := '£' || replace(trim(to_char(p.price, 'FM99999.00')), '.00', '') || case when p.price_unit = 'hour' then '/hr' else '' end;
  insert into listings (owner_id, kind, title, category, area, date, start_time, pay, description, positions, lat, lng, booked_package)
  values (auth.uid(), 'service', p.title, p.category,
    coalesce(nullif((select postcode from profiles where id = auth.uid()), ''), nullif(p.area, ''), 'Local'),
    d, t, payt, left(coalesce(note, ''), 1500), 1, p.lat, p.lng, p.id)
  returning id into lid;
  insert into listing_private (listing_id, address) values (lid, left(coalesce(addr, ''), 200));
  msg := 'Booking request: ' || p.title || ' (' || payt || ') on ' || to_char(d, 'Dy DD Mon') ||
    coalesce(' at ' || to_char(t, 'HH24:MI'), '') || case when coalesce(note, '') <> '' then E'\n' || left(note, 600) else '' end;
  insert into applications (listing_id, applicant_id, status, message, price, price_unit)
  values (lid, p.owner_id, 'invited', left(msg, 1000), p.price, p.price_unit) returning id into aid;
  insert into messages (application_id, sender_id, body) values (aid, auth.uid(), left(msg, 2000));
  return aid;
end $$;
revoke execute on function public.book_package(uuid, date, time, text, text) from public, anon;
grant execute on function public.book_package(uuid, date, time, text, text) to authenticated;

-- =====================================================================
-- v6: 48-hour quotes and protections for users aged 16 and 17
-- Needs v5 first. Safe to re-run. Supabase → SQL Editor → New query → Run.
-- =====================================================================

-- ---------- Age group (asked at sign-up; businesses count as 18+) ----------
alter table public.profiles add column if not exists age_group text;
alter table public.profiles drop constraint if exists profiles_age_group;
alter table public.profiles add constraint profiles_age_group check (age_group is null or age_group in ('16-17','18+'));
grant update (name, postcode, bio, avatar_url, account_type, headline, skills, available, available_days, lat, lng, portfolio, match_alerts, age_group)
  on public.profiles to authenticated;

create or replace function public.is_minor() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select age_group = '16-17' from profiles where id = auth.uid()), false)
$$;

-- Jobs and services involving alcohol, childcare or care are 18+.
create or replace function public.adult_only(l uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from listings x where x.id = l and (
    x.category in ('family','care')
    or (x.category = 'hospitality' and (x.details->>'role' = 'Bar staff' or (x.title || ' ' || x.description) ~* '\m(bar|pub|alcohol)\M'))))
$$;

drop policy if exists "applications insert" on public.applications;
create policy "applications insert" on public.applications for insert with check (
  not public.is_banned()
  and exists (select 1 from public.listings l where l.id = listing_id and l.status = 'open'
    and not public.blocked_between(l.owner_id, applicant_id))
  and not (public.adult_only(listing_id) and coalesce((select age_group from public.profiles where id = applicant_id), '') = '16-17')
  and (
    (applicant_id = auth.uid() and status = 'pending' and not public.is_listing_owner(listing_id))
    or (status = 'invited' and public.is_listing_owner(listing_id) and applicant_id <> auth.uid())
  ));

-- ---------- Quotes are valid for 48 hours ----------
alter table public.applications add column if not exists quoted_at timestamptz;
update public.applications set quoted_at = created_at where price is not null and quoted_at is null;

create or replace function public.stamp_quote() returns trigger
language plpgsql as $$
begin
  if new.price is not null and (tg_op = 'INSERT' or new.price is distinct from old.price or new.price_unit is distinct from old.price_unit) then
    new.quoted_at := now();
  end if;
  if new.price is null then new.quoted_at := null; end if;
  return new;
end $$;
drop trigger if exists application_stamp_quote on public.applications;
create trigger application_stamp_quote before insert or update on public.applications
  for each row execute function public.stamp_quote();

create or replace function public.check_application_update() returns trigger
language plpgsql security definer set search_path = public as $$
declare owner uuid;
begin
  if auth.uid() is null then return new; end if; -- dashboard / admin edits
  select owner_id into owner from listings where id = old.listing_id;
  if new.listing_id <> old.listing_id or new.applicant_id <> old.applicant_id or new.message <> old.message then
    raise exception 'Only the status can change';
  end if;
  if (new.price is distinct from old.price or new.price_unit is distinct from old.price_unit)
     and not (auth.uid() = old.applicant_id and new.status = 'pending') then
    raise exception 'Only the applicant can change their quote';
  end if;
  if auth.uid() = old.applicant_id then
    if old.status = 'invited' and new.status in ('accepted','declined') then return new; end if;
    if old.status in ('pending','declined','withdrawn') and new.status in ('withdrawn','pending') then return new; end if;
  end if;
  if auth.uid() = owner and old.status = 'pending' and new.status = 'accepted'
     and old.price is not null and coalesce(old.quoted_at, old.created_at) < now() - interval '48 hours' then
    raise exception 'This quote has expired. Ask for an updated quote first.';
  end if;
  if auth.uid() = owner and old.status <> 'invited' and new.status in ('accepted','declined','pending') then return new; end if;
  if auth.uid() = owner and old.status = 'invited' and new.status = 'withdrawn' then return new; end if;
  raise exception 'Not allowed';
end $$;

create or replace function public.book_package(pkg uuid, d date, t time, addr text, note text) returns uuid
language plpgsql security definer set search_path = public as $$
declare p record; lid uuid; aid uuid; msg text; payt text;
begin
  if auth.uid() is null then raise exception 'Not signed in'; end if;
  if is_banned() then raise exception 'Not allowed'; end if;
  select * into p from packages where id = pkg and active;
  if p.id is null then raise exception 'This service is no longer available'; end if;
  if p.owner_id = auth.uid() then raise exception 'You cannot book your own service'; end if;
  if blocked_between(p.owner_id, auth.uid()) then raise exception 'Not allowed'; end if;
  if d is null or d < current_date then raise exception 'Pick a date from today'; end if;
  if is_minor() and (p.category in ('family','care') or (p.category = 'hospitality' and (p.title || ' ' || p.description) ~* '\m(bar|pub|alcohol)\M')) then
    raise exception 'This service is for people aged 18 and over';
  end if;
  payt := '£' || replace(trim(to_char(p.price, 'FM99999.00')), '.00', '') || case when p.price_unit = 'hour' then '/hr' else '' end;
  insert into listings (owner_id, kind, title, category, area, date, start_time, pay, description, positions, lat, lng, booked_package)
  values (auth.uid(), 'service', p.title, p.category,
    coalesce(nullif((select postcode from profiles where id = auth.uid()), ''), nullif(p.area, ''), 'Local'),
    d, t, payt, left(coalesce(note, ''), 1500), 1, p.lat, p.lng, p.id)
  returning id into lid;
  insert into listing_private (listing_id, address) values (lid, left(coalesce(addr, ''), 200));
  msg := 'Booking request: ' || p.title || ' (' || payt || ') on ' || to_char(d, 'Dy DD Mon') ||
    coalesce(' at ' || to_char(t, 'HH24:MI'), '') || case when coalesce(note, '') <> '' then E'\n' || left(note, 600) else '' end;
  insert into applications (listing_id, applicant_id, status, message, price, price_unit)
  values (lid, p.owner_id, 'invited', left(msg, 1000), p.price, p.price_unit) returning id into aid;
  insert into messages (application_id, sender_id, body) values (aid, auth.uid(), left(msg, 2000));
  return aid;
end $$;
revoke execute on function public.book_package(uuid, date, time, text, text) from public, anon;
grant execute on function public.book_package(uuid, date, time, text, text) to authenticated;

-- =====================================================================
-- v7: phone notifications when the app is closed
-- Run AFTER deploying the send-push Edge Function (verify_jwt off). Safe to re-run.
-- No secrets in this file: the function only sends notifications that already
-- exist in the database, once each (pushed_at).
-- =====================================================================
create extension if not exists pg_net;

alter table public.notifications add column if not exists pushed_at timestamptz;

-- Remove the settings table used by the first draft of v7, if it was created.
drop table if exists private.settings;

create or replace function public.on_notification_push() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not exists (select 1 from push_subscriptions where user_id = new.user_id) then return new; end if;
  perform net.http_post(
    url := 'https://qayxsfanlheldqepegob.supabase.co/functions/v1/send-push',
    headers := jsonb_build_object('Content-Type', 'application/json'),
    body := jsonb_build_object('id', new.id)
  );
  return new;
exception when others then
  return new; -- never block the notification itself
end $$;
revoke execute on function public.on_notification_push() from public, anon, authenticated;

drop trigger if exists notification_push on public.notifications;
create trigger notification_push after insert on public.notifications
  for each row execute function public.on_notification_push();
