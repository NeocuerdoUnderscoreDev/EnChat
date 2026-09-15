-- EnChat E2EE key exchange.
-- Private keys and plaintext chat keys remain in the browser only.

create table if not exists public.user_keys (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  public_key_jwk jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.wrapped_chat_keys (
  chat_id uuid not null references public.chats(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  wrapped_key text not null,
  created_at timestamptz not null default now(),
  primary key (chat_id, user_id)
);

create index if not exists wrapped_chat_keys_user_idx on public.wrapped_chat_keys(user_id);

alter table public.user_keys enable row level security;
alter table public.wrapped_chat_keys enable row level security;

revoke all on public.user_keys from anon;
revoke all on public.wrapped_chat_keys from anon;
revoke insert, update, delete on public.wrapped_chat_keys from authenticated;

create policy user_keys_select_authorized on public.user_keys
for select to authenticated using (
  user_id = auth.uid()
  or exists (
    select 1
    from public.chat_members target_member
    where target_member.user_id = user_keys.user_id
      and target_member.left_at is null
      and public.is_active_chat_member(target_member.chat_id, auth.uid())
  )
);

create policy user_keys_insert_own on public.user_keys
for insert to authenticated with check (user_id = auth.uid());

create policy user_keys_update_own on public.user_keys
for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy wrapped_chat_keys_select_own on public.wrapped_chat_keys
for select to authenticated using (user_id = auth.uid());

create or replace function public.add_wrapped_chat_key(
  p_chat_id uuid,
  p_user_id uuid,
  p_wrapped_key text
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null or p_wrapped_key is null or length(p_wrapped_key) = 0 then
    raise exception 'invalid key request';
  end if;

  if not exists (
    select 1 from public.chats
    where id = p_chat_id and created_by = auth.uid() and destroyed_at is null
  ) then
    raise exception 'not authorized';
  end if;

  if not exists (
    select 1 from public.chat_members
    where chat_id = p_chat_id and user_id = p_user_id and left_at is null
  ) then
    raise exception 'member not found';
  end if;

  insert into public.wrapped_chat_keys (chat_id, user_id, wrapped_key)
  values (p_chat_id, p_user_id, p_wrapped_key)
  on conflict (chat_id, user_id) do update
    set wrapped_key = excluded.wrapped_key;
end;
$$;

create or replace function public.get_chat_members(p_chat_id uuid)
returns table (user_id uuid, public_key_jwk jsonb)
language sql
security definer
set search_path = public
as $$
  select uk.user_id, uk.public_key_jwk
  from public.user_keys uk
  join public.chat_members cm on cm.user_id = uk.user_id
  where cm.chat_id = p_chat_id
    and cm.left_at is null
    and public.is_active_chat_member(p_chat_id, auth.uid());
$$;

revoke execute on function public.add_wrapped_chat_key(uuid, uuid, text) from public, anon;
revoke execute on function public.get_chat_members(uuid) from public, anon;
grant execute on function public.add_wrapped_chat_key(uuid, uuid, text) to authenticated;
grant execute on function public.get_chat_members(uuid) to authenticated;

do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
    and not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'wrapped_chat_keys') then
    alter publication supabase_realtime add table public.wrapped_chat_keys;
  end if;
end
$$;
