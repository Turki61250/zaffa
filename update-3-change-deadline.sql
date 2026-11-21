-- ============================================================
--  Tashreef update 3: last date to CHANGE an answer
--  After the deadline a guest who already answered can't change it.
--  Guests who never answered can still answer.
--  Paste in Supabase → SQL Editor → Run (once). Safe to run again.
-- ============================================================
alter table public.events add column if not exists change_deadline timestamptz;

-- default for Mada & Khalid: end of 20 Dec 2026 (Riyadh time)
update public.events set change_deadline = '2026-12-20 23:59:59+03'
where slug = 'khalid-mada' and change_deadline is null;

create or replace function public._can_change(p_event uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select change_deadline is null or now() <= change_deadline from events where id = p_event), true)
$$;

create or replace function public.invite_get(p_token text, p_device text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare g guests; d text := nullif(trim(coalesce(p_device,'')), ''); dl timestamptz;
begin
  select * into g from guests where token = p_token for update;
  if g.id is null then return null; end if;
  select change_deadline into dl from events where id = g.event_id;
  if g.device_id is null and g.status <> 'pending' and d is not null then
    update guests set device_id = d where id = g.id;
    g.device_id := d;
  end if;
  if g.device_id is not null and g.device_id is distinct from d then
    return jsonb_build_object('name', g.name, 'locked', true, 'side', g.side);
  end if;
  return jsonb_build_object(
    'name', g.name, 'max', g.max_companions, 'status', g.status, 'companions', g.companions,
    'checked_in', g.checked_in_at is not null, 'locked', false, 'side', g.side,
    'deadline', dl, 'can_change', dl is null or now() <= dl,
    'secret', case when g.status = 'accepted' and g.device_id = d then g.secret end);
end $$;

create or replace function public.invite_respond(p_token text, p_attend boolean, p_companions int, p_device text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare g guests; d text := nullif(trim(coalesce(p_device,'')), '');
begin
  if d is null then raise exception 'no_device'; end if;
  select * into g from guests where token = p_token for update;
  if g.id is null then return null; end if;
  if g.device_id is not null and g.device_id <> d then
    return jsonb_build_object('name', g.name, 'locked', true);
  end if;
  -- already answered + deadline passed: keep the answer as it is
  if g.status <> 'pending' and not _can_change(g.event_id) then
    return invite_get(p_token, d);
  end if;
  if g.checked_in_at is null then
    update guests set
      device_id    = d,
      status       = case when p_attend then 'accepted' else 'declined' end,
      companions   = case when p_attend then greatest(0, least(coalesce(p_companions,0), g.max_companions)) else 0 end,
      responded_at = now()
    where id = g.id;
  end if;
  return invite_get(p_token, d);
end $$;

create or replace function public.admin_list(p_slug text, p_password text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare v_event uuid := _admin_event(p_slug, p_password); e events;
begin
  select * into e from events where id = v_event;
  return jsonb_build_object(
    'title', e.title, 'scan_key', e.scan_key, 'change_deadline', e.change_deadline,
    'guests', coalesce((select jsonb_agg(_guest_json(g) order by g.created_at) from guests g where g.event_id = v_event), '[]'::jsonb));
end $$;

create or replace function public.admin_set_deadline(p_slug text, p_password text, p_deadline timestamptz)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare v_event uuid := _admin_event(p_slug, p_password);
begin
  update events set change_deadline = p_deadline where id = v_event;
end $$;

revoke all on function public._can_change(uuid) from public, anon, authenticated;
grant execute on function public.invite_get(text, text) to anon;
grant execute on function public.invite_respond(text, boolean, int, text) to anon;
grant execute on function public.admin_list(text, text) to anon;
grant execute on function public.admin_set_deadline(text, text, timestamptz) to anon;
