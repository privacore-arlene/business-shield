-- PrivaCore Business Fraud Check — namespaced usage ceilings.
--
-- Every object here is prefixed `pc_business_` / `pc_` so it can live beside
-- the existing Fraud Doctor objects in the shared Supabase project without any
-- shared state, and can be lifted into a dedicated project unchanged.
--
-- Run in the Supabase SQL editor, or place in supabase/migrations/ and
-- `supabase db push`.

-- ---------------------------------------------------------------------------
-- Per-device daily allowance
-- ---------------------------------------------------------------------------
create table if not exists public.pc_business_daily_checks (
  device_id   text        not null,
  check_date  date        not null default (now() at time zone 'America/Vancouver')::date,
  used        integer     not null default 0,
  updated_at  timestamptz not null default now(),
  primary key (device_id, check_date)
);

-- Written only by the edge function through the service role; never exposed
-- to the Data API. No anon/authenticated grants on purpose.
grant all on public.pc_business_daily_checks to service_role;
alter table public.pc_business_daily_checks enable row level security;
-- No policies: RLS denies every anon/authenticated request by default.

-- ---------------------------------------------------------------------------
-- Per-network ceilings (pseudonymous HMAC of the caller IP, never the IP)
-- ---------------------------------------------------------------------------
create table if not exists public.pc_business_ip_checks (
  ip_hash        text        primary key,
  check_date     date        not null default (now() at time zone 'America/Vancouver')::date,
  daily_used     integer     not null default 0,
  burst_used     integer     not null default 0,
  burst_start_at timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

grant all on public.pc_business_ip_checks to service_role;
alter table public.pc_business_ip_checks enable row level security;

-- ---------------------------------------------------------------------------
-- pc_consume_business_daily_check
-- ---------------------------------------------------------------------------
create or replace function public.pc_consume_business_daily_check(
  _device_id text,
  _limit     integer default 5
)
returns table (allowed boolean, used integer, remaining integer)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_today date := (now() at time zone 'America/Vancouver')::date;
  v_used  integer;
begin
  if _device_id is null or length(_device_id) < 3 then
    return query select false, _limit, 0;
    return;
  end if;

  insert into public.pc_business_daily_checks as d (device_id, check_date, used)
  values (left(_device_id, 120), v_today, 1)
  on conflict (device_id, check_date) do update
    set used = case when d.used < _limit then d.used + 1 else d.used end,
        updated_at = now()
  returning d.used into v_used;

  if v_used > _limit then
    return query select false, _limit, 0;
  else
    return query select true, v_used, greatest(_limit - v_used, 0);
  end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- pc_consume_business_ip_check
-- ---------------------------------------------------------------------------
create or replace function public.pc_consume_business_ip_check(
  _ip_hash     text,
  _daily_limit integer default 20,
  _burst_limit integer default 8
)
returns table (allowed boolean, reason text, resets_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_today       date := (now() at time zone 'America/Vancouver')::date;
  v_burst_start timestamptz;
  v_burst_used  integer;
  v_daily_used  integer;
  v_row         public.pc_business_ip_checks%rowtype;
begin
  if _ip_hash is null or length(_ip_hash) < 16 then
    return query select false, 'invalid'::text, now();
    return;
  end if;

  select * into v_row from public.pc_business_ip_checks where ip_hash = _ip_hash for update;

  if not found then
    insert into public.pc_business_ip_checks (ip_hash, check_date, daily_used, burst_used, burst_start_at)
    values (_ip_hash, v_today, 1, 1, now());
    return query select true, ''::text, (v_today + 1)::timestamptz;
    return;
  end if;

  -- Roll the daily window.
  if v_row.check_date <> v_today then
    v_daily_used := 0;
  else
    v_daily_used := v_row.daily_used;
  end if;

  -- Roll the 10-minute burst window.
  if now() - v_row.burst_start_at > interval '10 minutes' then
    v_burst_start := now();
    v_burst_used  := 0;
  else
    v_burst_start := v_row.burst_start_at;
    v_burst_used  := v_row.burst_used;
  end if;

  if v_daily_used >= _daily_limit then
    return query select false, 'daily'::text, ((v_today + 1)::timestamptz);
    return;
  end if;

  if v_burst_used >= _burst_limit then
    return query select false, 'burst'::text, (v_burst_start + interval '10 minutes');
    return;
  end if;

  update public.pc_business_ip_checks
     set check_date     = v_today,
         daily_used     = v_daily_used + 1,
         burst_used     = v_burst_used + 1,
         burst_start_at = v_burst_start,
         updated_at     = now()
   where ip_hash = _ip_hash;

  return query select true, ''::text, ((v_today + 1)::timestamptz);
end;
$$;

-- Callable only by the edge function's service role.
revoke all on function public.pc_consume_business_daily_check(text, integer) from public, anon, authenticated;
revoke all on function public.pc_consume_business_ip_check(text, integer, integer) from public, anon, authenticated;
grant execute on function public.pc_consume_business_daily_check(text, integer) to service_role;
grant execute on function public.pc_consume_business_ip_check(text, integer, integer) to service_role;

-- ---------------------------------------------------------------------------
-- Retention: usage rows are operational only.
-- ---------------------------------------------------------------------------
create or replace function public.pc_purge_business_usage()
returns void
language sql
security definer
set search_path = public
as $$
  delete from public.pc_business_daily_checks
   where check_date < (now() at time zone 'America/Vancouver')::date - 30;
  delete from public.pc_business_ip_checks
   where updated_at < now() - interval '30 days';
$$;

revoke all on function public.pc_purge_business_usage() from public, anon, authenticated;
grant execute on function public.pc_purge_business_usage() to service_role;