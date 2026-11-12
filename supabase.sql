-- ============================================================
--  Zaffa (زفّة) — database setup
--  Paste this whole file in Supabase → SQL Editor → Run.
--  BEFORE running: change the admin password on the last lines.
-- ============================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- ---------- tables ----------
create table if not exists public.events (
  id          uuid primary key default extensions.gen_random_uuid(),
  slug        text unique not null,
  title       text not null,
  admin_hash  text not null,
  scan_key    text not null default encode(extensions.gen_random_bytes(12), 'hex'),
  created_at  timestamptz not null default now()
);

create table if not exists public.guests (
  id              uuid primary key default extensions.gen_random_uuid(),
  event_id        uuid not null references public.events(id) on delete cascade,
  name            text not null,
  phone           text,
  max_companions  int  not null default 0 check (max_companions between 0 and 20),
  token           text unique not null default encode(extensions.gen_random_bytes(9), 'hex'),
  secret          text not null default encode(extensions.gen_random_bytes(16), 'hex'),
  status          text not null default 'pending' check (status in ('pending','accepted','declined')),
  companions      int  not null default 0,
  responded_at    timestamptz,
  sent_at         timestamptz,
  checked_in_at   timestamptz,
  created_at      timestamptz not null default now()
);
create index if not exists guests_event_idx on public.guests(event_id);

-- Lock the tables: nobody reads them directly. Everything goes through the functions below.
alter table public.events enable row level security;
alter table public.guests enable row level security;
revoke all on public.events from anon, authenticated;
revoke all on public.guests from anon, authenticated;

-- ---------- helpers ----------
create or replace function public._admin_event(p_slug text, p_password text)
returns uuid language plpgsql security definer set search_path = public, extensions as $$
declare v_id uuid; v_hash text;
begin
  select id, admin_hash into v_id, v_hash from events where slug = p_slug;
  if v_id is null or crypt(p_password, v_hash) <> v_hash then
    raise exception 'unauthorized';
  end if;
  return v_id;
end $$;

create or replace function public._guest_json(g public.guests)
returns jsonb language sql stable as $$
  select jsonb_build_object(
    'id', g.id, 'name', g.name, 'phone', g.phone, 'max', g.max_companions,
    'token', g.token, 'status', g.status, 'companions', g.companions,
    'responded_at', g.responded_at, 'sent_at', g.sent_at, 'checked_in_at', g.checked_in_at)
$$;

-- ---------- guest: invitation page ----------
create or replace function public.invite_get(p_token text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare g guests;
begin
  select * into g from guests where token = p_token;
  if g.id is null then return null; end if;
  return jsonb_build_object(
    'name', g.name, 'max', g.max_companions, 'status', g.status, 'companions', g.companions,
    'checked_in', g.checked_in_at is not null,
    'secret', case when g.status = 'accepted' then g.secret end);
end $$;

create or replace function public.invite_respond(p_token text, p_attend boolean, p_companions int)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare g guests;
begin
  select * into g from guests where token = p_token for update;
  if g.id is null then return null; end if;
  if g.checked_in_at is not null then return invite_get(p_token); end if;  -- already inside: no changes
  update guests set
    status       = case when p_attend then 'accepted' else 'declined' end,
    companions   = case when p_attend then greatest(0, least(coalesce(p_companions,0), g.max_companions)) else 0 end,
    responded_at = now()
  where id = g.id;
  return invite_get(p_token);
end $$;

-- ---------- door scanner ----------
-- QR payload format:  ZF1.<token>.<step>.<sig>
--   step = floor(unix_seconds / 30),  sig = first 20 hex of HMAC-SHA256(token.step, secret)
create or replace function public.scan_check(p_scan_key text, p_payload text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  v_token text := split_part(p_payload, '.', 2);
  v_step  bigint;
  v_sig   text := split_part(p_payload, '.', 4);
  v_now   bigint := floor(extract(epoch from now()) / 30);
  g guests; e events;
begin
  select * into e from events where scan_key = p_scan_key;
  if e.id is null then return jsonb_build_object('result','bad_key'); end if;
  if split_part(p_payload, '.', 1) <> 'ZF1' then return jsonb_build_object('result','invalid'); end if;
  begin v_step := split_part(p_payload, '.', 3)::bigint;
  exception when others then return jsonb_build_object('result','invalid'); end;

  select * into g from guests where token = v_token and event_id = e.id for update;
  if g.id is null then return jsonb_build_object('result','invalid'); end if;
  if v_sig <> left(encode(hmac(v_token || '.' || v_step::text, g.secret, 'sha256'), 'hex'), 20) then
    return jsonb_build_object('result','invalid');
  end if;
  if abs(v_step - v_now) > 2 then
    return jsonb_build_object('result','expired', 'name', g.name);
  end if;
  if g.status <> 'accepted' then
    return jsonb_build_object('result','not_accepted', 'name', g.name);
  end if;
  if g.checked_in_at is not null then
    return jsonb_build_object('result','used', 'name', g.name, 'at', g.checked_in_at);
  end if;
  update guests set checked_in_at = now() where id = g.id;
  return jsonb_build_object('result','ok', 'name', g.name, 'people', 1 + g.companions);
end $$;

create or replace function public.scan_stats(p_scan_key text)
returns jsonb language sql security definer set search_path = public, extensions as $$
  select jsonb_build_object(
    'title', e.title,
    'expected', coalesce(sum(1 + g.companions) filter (where g.status = 'accepted'), 0),
    'inside',   coalesce(sum(1 + g.companions) filter (where g.checked_in_at is not null), 0))
  from events e left join guests g on g.event_id = e.id
  where e.scan_key = p_scan_key
  group by e.id, e.title
$$;

-- ---------- dashboard (password protected) ----------
create or replace function public.admin_list(p_slug text, p_password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare v_event uuid := _admin_event(p_slug, p_password); e events;
begin
  select * into e from events where id = v_event;
  return jsonb_build_object(
    'title', e.title, 'scan_key', e.scan_key,
    'guests', coalesce((select jsonb_agg(_guest_json(g) order by g.created_at) from guests g where g.event_id = v_event), '[]'::jsonb));
end $$;

create or replace function public.admin_add(p_slug text, p_password text, p_guests jsonb)
returns int language plpgsql security definer set search_path = public, extensions as $$
declare v_event uuid := _admin_event(p_slug, p_password); n int;
begin
  insert into guests(event_id, name, phone, max_companions)
  select v_event, trim(x->>'name'), nullif(trim(x->>'phone'), ''), greatest(0, least(20, coalesce((x->>'max')::int, 0)))
  from jsonb_array_elements(p_guests) x
  where coalesce(trim(x->>'name'), '') <> '';
  get diagnostics n = row_count;
  return n;
end $$;

create or replace function public.admin_update(p_slug text, p_password text, p_id uuid, p_name text, p_phone text, p_max int)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare v_event uuid := _admin_event(p_slug, p_password);
begin
  update guests set name = trim(p_name), phone = nullif(trim(p_phone), ''),
         max_companions = greatest(0, least(20, coalesce(p_max, 0))),
         companions = least(companions, greatest(0, least(20, coalesce(p_max, 0))))
  where id = p_id and event_id = v_event;
end $$;

create or replace function public.admin_delete(p_slug text, p_password text, p_id uuid)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare v_event uuid := _admin_event(p_slug, p_password);
begin
  delete from guests where id = p_id and event_id = v_event;
end $$;

create or replace function public.admin_mark_sent(p_slug text, p_password text, p_id uuid)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare v_event uuid := _admin_event(p_slug, p_password);
begin
  update guests set sent_at = now() where id = p_id and event_id = v_event;
end $$;

create or replace function public.admin_reset(p_slug text, p_password text, p_id uuid)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare v_event uuid := _admin_event(p_slug, p_password);
begin
  update guests set status = 'pending', companions = 0, responded_at = null, checked_in_at = null
  where id = p_id and event_id = v_event;
end $$;

-- Only these functions are callable from the website.
revoke all on function public._admin_event(text, text) from public, anon, authenticated;
revoke all on function public._guest_json(public.guests) from public, anon, authenticated;
grant execute on function public.invite_get(text) to anon;
grant execute on function public.invite_respond(text, boolean, int) to anon;
grant execute on function public.scan_check(text, text) to anon;
grant execute on function public.scan_stats(text) to anon;
grant execute on function public.admin_list(text, text) to anon;
grant execute on function public.admin_add(text, text, jsonb) to anon;
grant execute on function public.admin_update(text, text, uuid, text, text, int) to anon;
grant execute on function public.admin_delete(text, text, uuid) to anon;
grant execute on function public.admin_mark_sent(text, text, uuid) to anon;
grant execute on function public.admin_reset(text, text, uuid) to anon;

-- ---------- your event ----------
-- ⚠️ In the line below, replace the word CHANGE_ME (keep the quotes) with your own dashboard password, then press Run.
insert into public.events (slug, title, admin_hash)
values ('khalid-mada', 'زفاف خالد ومدى', extensions.crypt('CHANGE_ME', extensions.gen_salt('bf')))
on conflict (slug) do nothing;
