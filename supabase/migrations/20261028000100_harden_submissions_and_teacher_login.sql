-- 제출 검증, 중복 제출 방지, 문제 버전 기록, 교사 로그인 시도 제한
-- Supabase 대시보드 > SQL Editor에 통째로 붙여 넣고 실행한다. 한 트랜잭션으로 돌아서 중간에 실패하면 아무것도 바뀌지 않는다.

begin;

-- ---------- 1. 제출 기록에 칸 추가 ----------
alter table private.submissions
  add column if not exists client_id text check (client_id is null or length(client_id) <= 64),
  add column if not exists problem_version integer,
  add column if not exists client_at timestamptz;
-- 같은 제출(같은 client_id)이 두 번 와도 한 번만 저장
create unique index if not exists submissions_client_id on private.submissions (client_id) where client_id is not null;

-- 지금 서버에 저장된 문제의 테스트 개수 (문제가 없으면 null)
create or replace function private.test_count(p_problem text)
 returns integer
 language sql
 stable security definer
 set search_path to ''
as $function$
  select jsonb_array_length(t->'tests')
  from private.problem_set ps, jsonb_array_elements(ps.data) t
  where ps.id = 1 and t->>'id' = p_problem
  limit 1;
$function$;
revoke all on function private.test_count(text) from public, anon, authenticated;

-- ---------- 2. 새 제출 함수 ----------
-- 통과 수와 전체 수를 브라우저가 따로 보내지 않고, 케이스 결과 배열에서 서버가 센다.
-- 돌려주는 값: ok(저장됨, 이미 저장된 같은 제출 포함) / rate(1분에 40번 초과) / nocode / stale(문제가 바뀜) / bad
create or replace function public.submit_run(
  p_code text, p_problem text, p_version integer, p_cases jsonb, p_source text,
  p_client_id text default null, p_client_at timestamptz default null)
 returns text
 language plpgsql
 security definer
 set search_path to ''
as $function$
declare
  c text := upper(trim(p_code));
  n integer;
  v_passed integer;
begin
  if p_client_id is not null then
    if length(p_client_id) > 64 then return 'bad'; end if;
    if exists (select 1 from private.submissions where client_id = p_client_id) then return 'ok'; end if;
  end if;
  if not exists (select 1 from private.students where code = c) then return 'nocode'; end if;
  if (select count(*) from private.submissions
        where code = c and created_at > now() - interval '1 minute') >= 40 then
    return 'rate';
  end if;
  if coalesce(length(p_problem), 0) not between 1 and 64 then return 'bad'; end if;
  if length(trim(coalesce(p_source, ''))) = 0 then return 'bad'; end if;
  if jsonb_typeof(p_cases) is distinct from 'array' or octet_length(p_cases::text) > 30000 then return 'bad'; end if;
  if exists (select 1 from jsonb_array_elements(p_cases) x
             where jsonb_typeof(x) <> 'object' or coalesce(x->>'s', '') not in ('pass', 'wrong', 'err', 'tle')) then
    return 'bad';
  end if;

  if exists (select 1 from private.problem_set where id = 1) then
    n := private.test_count(p_problem);
    -- 없는 문제이거나 케이스 수가 지금 문제와 다르면 문제가 바뀐 뒤의 옛 결과로 본다
    if n is null or jsonb_array_length(p_cases) <> n then return 'stale'; end if;
  else
    n := jsonb_array_length(p_cases);
  end if;
  if n = 0 then return 'bad'; end if;

  select count(*) into v_passed from jsonb_array_elements(p_cases) x where x->>'s' = 'pass';

  insert into private.submissions (code, problem_id, passed, total, cases, source, client_id, problem_version, client_at)
  values (c, p_problem, v_passed, n, p_cases, left(p_source, 20000), p_client_id, p_version,
          case when p_client_at is null or p_client_at > now() then now() else p_client_at end)
  on conflict (client_id) where client_id is not null do nothing;
  return 'ok';
end;
$function$;

-- ---------- 3. 예전 제출 함수에도 같은 검사 ----------
-- 새로고침하지 않은 옛 페이지가 보내는 기록도 걸러진다. 반환 형식(true/false)은 그대로 둔다.
create or replace function public.submit_result(p_code text, p_problem text, p_passed integer, p_total integer, p_cases jsonb, p_source text)
 returns boolean
 language plpgsql
 security definer
 set search_path to ''
as $function$
begin
  if jsonb_typeof(p_cases) is distinct from 'array'
     or jsonb_array_length(p_cases) <> p_total
     or p_passed <> (select count(*) from jsonb_array_elements(p_cases) x where x->>'s' = 'pass') then
    return false;
  end if;
  return public.submit_run(p_code, p_problem, null, p_cases, p_source, null, null) = 'ok';
end;
$function$;

-- ---------- 4. 교사 로그인: 토큰 발급 + 틀린 횟수 제한 ----------
-- 비밀번호 확인은 로그인 때 한 번만 하고, 이후 teacher_* 함수는 12시간짜리 토큰으로 확인한다.
-- 그래서 teacher_overview 같은 함수로 비밀번호를 대입해 볼 수 없다.
create table if not exists private.teacher_sessions (
  token text primary key,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create table if not exists private.login_failures (
  id bigint generated always as identity primary key,
  who text not null,
  at timestamptz not null default now()
);
create index if not exists login_failures_who_at on private.login_failures (who, at desc);
alter table private.teacher_sessions enable row level security;
alter table private.login_failures enable row level security;

-- 예전 teacher_ok(비밀번호 확인)를 이름만 바꿔 둔다
create or replace function private.teacher_password_ok(p_key text)
 returns boolean
 language sql
 stable security definer
 set search_path to ''
as $function$
  select exists (
    select 1 from private.settings s1 join private.settings s2 on s2.k = 'teacher_salt'
    where s1.k = 'teacher_hash'
      and s1.v = encode(extensions.digest(s2.v || coalesce(p_key, ''), 'sha256'), 'hex')
  );
$function$;
revoke all on function private.teacher_password_ok(text) from public, anon, authenticated;

-- teacher_ok는 이제 토큰을 확인한다. teacher_* 함수들은 고치지 않아도 그대로 동작한다.
create or replace function private.teacher_ok(p_key text)
 returns boolean
 language sql
 stable security definer
 set search_path to ''
as $function$
  select exists (select 1 from private.teacher_sessions where token = p_key and expires_at > now());
$function$;
revoke all on function private.teacher_ok(text) from public, anon, authenticated;

drop function if exists public.teacher_login(text);
create function public.teacher_login(p_key text)
 returns text
 language plpgsql
 volatile security definer
 set search_path to ''
as $function$
declare
  hdr json := nullif(current_setting('request.headers', true), '')::json;
  v_who text := coalesce(nullif(trim(split_part(coalesce(hdr->>'x-forwarded-for', ''), ',', 1)), ''), 'unknown');
  tok text;
begin
  delete from private.login_failures where at < now() - interval '1 day';
  -- 같은 곳에서 10분에 10번 넘게 틀리면 잠시 막는다
  if (select count(*) from private.login_failures where who = v_who and at > now() - interval '10 minutes') >= 10 then
    raise exception 'locked' using errcode = 'P0001';
  end if;
  if not private.teacher_password_ok(p_key) then
    insert into private.login_failures (who) values (v_who);
    return null;
  end if;
  delete from private.teacher_sessions where expires_at < now();
  tok := encode(extensions.gen_random_bytes(24), 'hex');
  insert into private.teacher_sessions (token, expires_at) values (tok, now() + interval '12 hours');
  return tok;
end;
$function$;

commit;

-- 되돌리기가 필요하면: 20261028000000_snapshot_before_fixes.sql의 teacher_ok, teacher_login, submit_result를 다시 실행하고
-- drop function public.submit_run(text, text, integer, jsonb, text, text, timestamptz); 를 실행한다. 추가한 칸과 표는 남겨 둬도 된다.
