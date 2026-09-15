-- EnChat database schema.
-- Apply with the Supabase SQL editor or `supabase db push`.
-- No service-role key is required by the browser.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  created_at timestamptz not null default now(),
  constraint profiles_username_length check (char_length(username) between 3 and 24),
  constraint profiles_username_format check (username ~ '^[A-Za-z0-9_-]+$')
);

create unique index if not exists profiles_username_ci_idx
  on public.profiles (lower(username));

create table if not exists public.chat_code_history (
  chat_code text primary key,
  first_chat_id uuid not null,
  issued_at timestamptz not null default now(),
  constraint chat_code_history_format check (chat_code ~ '^[0-9]{6}$')
);

create table if not exists public.chats (
  id uuid primary key default gen_random_uuid(),
  chat_code text not null unique,
  created_by uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  destroyed_at timestamptz,
  constraint chats_code_format check (chat_code ~ '^[0-9]{6}$')
);

create table if not exists public.chat_members (
  chat_id uuid not null references public.chats(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  left_at timestamptz,
  primary key (chat_id, user_id),
  constraint chat_members_left_after_join check (left_at is null or left_at >= joined_at)
);

create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  chat_id uuid not null references public.chats(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  ciphertext text not null,
  nonce text not null,
  created_at timestamptz not null default now(),
  constraint messages_ciphertext_present check (length(ciphertext) > 0),
  constraint messages_nonce_present check (length(nonce) > 0)
);

create index if not exists chats_created_by_idx on public.chats(created_by);
create index if not exists chats_active_code_idx on public.chats(chat_code) where destroyed_at is null;
create index if not exists chat_members_user_active_idx on public.chat_members(user_id) where left_at is null;
create index if not exists chat_members_chat_active_idx on public.chat_members(chat_id) where left_at is null;
create index if not exists messages_chat_created_idx on public.messages(chat_id, created_at desc, id desc);

create or replace function public.register_chat_code()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if exists (select 1 from public.chat_code_history where chat_code = new.chat_code) then
    raise exception 'chat code unavailable';
  end if;

  insert into public.chat_code_history (chat_code, first_chat_id)
  values (new.chat_code, new.id);
  return new;
end;
$$;

 drop trigger if exists chats_register_code on public.chats;
create trigger chats_register_code
before insert on public.chats
for each row execute function public.register_chat_code();

create or replace function public.add_owner_as_member()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.chat_members (chat_id, user_id)
  values (new.id, new.created_by);
  return new;
end;
$$;

 drop trigger if exists chats_add_owner on public.chats;
create trigger chats_add_owner
after insert on public.chats
for each row execute function public.add_owner_as_member();

create or replace function public.create_chat()
returns public.chats
language plpgsql
security definer
set search_path = public
as $$
declare
  new_chat public.chats;
  candidate text;
  entropy bytea;
begin
  if auth.uid() is null then
    raise exception 'not authenticated';
  end if;

  if not exists (select 1 from public.profiles where id = auth.uid()) then
    raise exception 'profile required';
  end if;

  loop
    entropy := gen_random_bytes(4);
    candidate := lpad((
      (get_byte(entropy, 0)::bigint << 24)
      + (get_byte(entropy, 1)::bigint << 16)
      + (get_byte(entropy, 2)::bigint << 8)
      + get_byte(entropy, 3)::bigint
    % 1000000::bigint)::text, 6, '0');

    begin
      insert into public.chats (chat_code, created_by)
      values (candidate, auth.uid())
      returning * into new_chat;
      return new_chat;
    exception when unique_violation then
      -- A collision is harmless; try another cryptographically random code.
      null;
    end;
  end loop;
end;
$$;

create or replace function public.join_chat(p_chat_code text)
returns public.chats
language plpgsql
security definer
set search_path = public
as $$
declare
  target public.chats;
  active_member_count integer;
begin
  if auth.uid() is null then
    raise exception 'not authenticated';
  end if;

  if not exists (select 1 from public.profiles where id = auth.uid()) then
    raise exception 'profile required';
  end if;

  if p_chat_code is null or p_chat_code !~ '^[0-9]{6}$' then
    raise exception 'chat not found';
  end if;

  select * into target
  from public.chats
  where chat_code = p_chat_code and destroyed_at is null
  for update;

  if not found then
    raise exception 'chat not found';
  end if;

  select count(*)::integer into active_member_count
  from public.chat_members
  where chat_id = target.id and left_at is null;

  if active_member_count >= 2
     and not exists (
       select 1 from public.chat_members
       where chat_id = target.id and user_id = auth.uid() and left_at is null
     ) then
    raise exception 'chat unavailable';
  end if;

  insert into public.chat_members (chat_id, user_id)
  values (target.id, auth.uid())
  on conflict (chat_id, user_id) do update
    set left_at = null
    where public.chat_members.left_at is not null;

  return target;
end;
$$;

create or replace function public.leave_chat(p_chat_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.chat_members
  set left_at = now()
  where chat_id = p_chat_id and user_id = auth.uid() and left_at is null;

  if not found then
    raise exception 'membership not found';
  end if;
end;
$$;

create or replace function public.destroy_chat(p_chat_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not exists (
    select 1 from public.chats
    where id = p_chat_id and created_by = auth.uid() and destroyed_at is null
  ) then
    raise exception 'not authorized';
  end if;

  -- Cascades remove messages, members, and chat metadata. chat_code_history remains.
  delete from public.chats where id = p_chat_id;
end;
$$;

create or replace function public.is_active_chat_member(p_chat_id uuid, p_user_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.chat_members
    where chat_id = p_chat_id and user_id = p_user_id and left_at is null
  );
$$;

alter table public.profiles enable row level security;
alter table public.chat_code_history enable row level security;
alter table public.chats enable row level security;
alter table public.chat_members enable row level security;
alter table public.messages enable row level security;

revoke all on public.chat_code_history from anon, authenticated;
revoke insert, delete on public.chats from anon, authenticated;
revoke insert, delete on public.chat_members from anon, authenticated;
revoke update, delete on public.messages from anon, authenticated;

create policy profiles_select_own on public.profiles
for select to authenticated using (id = auth.uid());

create policy profiles_insert_own on public.profiles
for insert to authenticated with check (id = auth.uid());

create policy chats_select_active_member on public.chats
for select to authenticated using (
  destroyed_at is null and public.is_active_chat_member(id, auth.uid())
);

create policy chats_update_owner_destroy on public.chats
for update to authenticated
using (created_by = auth.uid() and destroyed_at is null)
with check (created_by = auth.uid() and destroyed_at is not null);

create policy memberships_select_same_chat on public.chat_members
for select to authenticated using (public.is_active_chat_member(chat_id, auth.uid()));

create policy messages_select_active_member on public.messages
for select to authenticated using (
  public.is_active_chat_member(chat_id, auth.uid())
  and exists (select 1 from public.chats c where c.id = messages.chat_id and c.destroyed_at is null)
);

create policy messages_insert_active_member on public.messages
for insert to authenticated with check (
  sender_id = auth.uid()
  and public.is_active_chat_member(chat_id, auth.uid())
  and exists (select 1 from public.chats c where c.id = messages.chat_id and c.destroyed_at is null)
);

-- Realtime emits ciphertext and metadata only; plaintext is never stored here.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages') then
      alter publication supabase_realtime add table public.messages;
    end if;
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'chat_members') then
      alter publication supabase_realtime add table public.chat_members;
    end if;
  end if;
end
$$;

revoke execute on function public.create_chat() from public, anon;
revoke execute on function public.join_chat(text) from public, anon;
revoke execute on function public.leave_chat(uuid) from public, anon;
revoke execute on function public.destroy_chat(uuid) from public, anon;
revoke execute on function public.is_active_chat_member(uuid, uuid) from public, anon;

grant execute on function public.create_chat() to authenticated;
grant execute on function public.join_chat(text) to authenticated;
grant execute on function public.leave_chat(uuid) to authenticated;
grant execute on function public.destroy_chat(uuid) to authenticated;
grant execute on function public.is_active_chat_member(uuid, uuid) to authenticated;