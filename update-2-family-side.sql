-- ============================================================
--  Tashreef update 2: split guests into bride's family / groom's family
--  Paste in Supabase → SQL Editor → Run (once). Safe to run again.
--  Existing guests become "bride" (أهل العروس).
-- ============================================================
alter table public.guests add column if not exists side text not null default 'bride';
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'guests_side_check') then
    alter table public.guests add constraint guests_side_check check (side in ('bride','groom'));
  end if;
end $$;

create or replace function public._guest_json(g public.guests)
returns jsonb language sql stable as $$
  select jsonb_build_object(
    'id', g.id, 'name', g.name, 'phone', g.phone, 'max', g.max_companions,
    'token', g.token, 'status', g.status, 'companions', g.companions,
    'responded_at', g.responded_at, 'sent_at', g.sent_at, 'checked_in_at', g.checked_in_at,
    'locked', g.device_id is not null, 'side', g.side)
$$;

create or replace function public.invite_get(p_token text, p_device text)
returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare g guests; d text := nullif(trim(coalesce(p_device,'')), '');
begin
  select * into g from guests where token = p_token for update;
  if g.id is null then return null; end if;
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
    'secret', case when g.status = 'accepted' and g.device_id = d then g.secret end);
end $$;

create or replace function public.admin_add(p_slug text, p_password text, p_guests jsonb)
returns int language plpgsql security definer set search_path = public, extensions as $$
declare v_event uuid := _admin_event(p_slug, p_password); n int;
begin
  insert into guests(event_id, name, phone, max_companions, side)
  select v_event, trim(x->>'name'), nullif(trim(x->>'phone'), ''),
         greatest(0, least(20, coalesce((x->>'max')::int, 0))),
         case when x->>'side' = 'groom' then 'groom' else 'bride' end
  from jsonb_array_elements(p_guests) x
  where coalesce(trim(x->>'name'), '') <> '';
  get diagnostics n = row_count;
  return n;
end $$;

create or replace function public.admin_set_side(p_slug text, p_password text, p_id uuid, p_side text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare v_event uuid := _admin_event(p_slug, p_password);
begin
  if p_side not in ('bride','groom') then raise exception 'bad_side'; end if;
  update guests set side = p_side where id = p_id and event_id = v_event;
end $$;

revoke all on function public._guest_json(public.guests) from public, anon, authenticated;
grant execute on function public.invite_get(text, text) to anon;
grant execute on function public.admin_add(text, text, jsonb) to anon;
grant execute on function public.admin_set_side(text, text, uuid, text) to anon;
