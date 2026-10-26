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
