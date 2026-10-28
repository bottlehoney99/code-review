-- 2026-10-28 기준 운영 DB(bxydptizntolzhaonbgj)의 표와 함수를 그대로 옮겨 적은 기록.
-- 새 Supabase 프로젝트를 만들 때는 이 파일부터 실행한 뒤 다음 마이그레이션을 실행한다.
-- 운영 DB에는 이미 들어 있으니 다시 실행하지 않는다.
-- 교사 비밀번호(teacher_salt, teacher_hash)는 이 파일에 넣지 않았다. 맨 아래 주석을 보고 따로 넣는다.

create extension if not exists pgcrypto with schema extensions;
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table private.students (
  code text primary key check (code ~ '^[A-Z0-9]{5}$'),
  created_at timestamptz not null default now(),
  alias text,
  default_alias text,
  alias_changed_at timestamptz
);
create unique index students_alias_unique on private.students (lower(alias));

create table private.submissions (
  id bigint generated always as identity primary key,
  code text not null references private.students(code) on delete cascade,
  problem_id text not null check (length(problem_id) >= 1 and length(problem_id) <= 64),
  passed integer not null check (passed >= 0),
  total integer not null,
  all_pass boolean generated always as (passed = total) stored,
  cases jsonb not null default '[]'::jsonb,
  source text not null default '' check (length(source) <= 20000),
  created_at timestamptz not null default now(),
  check (total > 0 and passed <= total)
);
create index submissions_code_time on private.submissions (code, created_at desc);
create index submissions_time on private.submissions (created_at desc);

create table private.settings (k text primary key, v text not null);

create table private.problem_set (
  id integer primary key default 1 check (id = 1),
  data jsonb not null,
  version integer not null default 1,
  updated_at timestamptz not null default now()
);

create table private.problem_set_history (
  id bigint generated always as identity primary key,
  data jsonb not null,
  version integer not null,
  saved_at timestamptz not null default now()
);

alter table private.students enable row level security;
alter table private.submissions enable row level security;
alter table private.settings enable row level security;
alter table private.problem_set enable row level security;
alter table private.problem_set_history enable row level security;

CREATE OR REPLACE FUNCTION private.teacher_ok(p_key text)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (
    select 1 from private.settings s1 join private.settings s2 on s2.k = 'teacher_salt'
    where s1.k = 'teacher_hash'
      and s1.v = encode(extensions.digest(s2.v || coalesce(p_key, ''), 'sha256'), 'hex')
  );
$function$;
revoke all on function private.teacher_ok(text) from public, anon, authenticated;

CREATE OR REPLACE FUNCTION public.check_code(p_code text)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select exists (select 1 from private.students where code = upper(trim(p_code)));
$function$;

CREATE OR REPLACE FUNCTION public.get_problems()
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select jsonb_build_object('version', version, 'updated_at', updated_at, 'problems', data)
  from private.problem_set where id = 1;
$function$;

CREATE OR REPLACE FUNCTION public.monthly_mvp()
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  with fp as (
    select code, problem_id, min(created_at) as t
    from private.submissions where all_pass group by code, problem_id
  ), months as (
    select m, m = date_trunc('month', now() at time zone 'Asia/Seoul') as is_current
    from (values (date_trunc('month', now() at time zone 'Asia/Seoul')),
                 (date_trunc('month', now() at time zone 'Asia/Seoul') - interval '1 month')) v(m)
  ), ranked as (
    select mo.m, mo.is_current, fp.code, count(*)::int as solved, max(fp.t) as reached,
           row_number() over (partition by mo.m order by count(*) desc, max(fp.t) asc) as rk
    from months mo
    join fp on (fp.t at time zone 'Asia/Seoul') >= mo.m and (fp.t at time zone 'Asia/Seoul') < mo.m + interval '1 month'
    group by mo.m, mo.is_current, fp.code
  )
  select jsonb_build_object('month', extract(month from r.m)::int, 'year', extract(year from r.m)::int,
                            'current', r.is_current, 'alias', coalesce(st.alias, '이름 없는 학생'), 'solved', r.solved)
  from ranked r join private.students st on st.code = r.code
  where r.rk = 1
  order by r.is_current desc limit 1;
$function$;

CREATE OR REPLACE FUNCTION public.my_progress(p_code text)
 RETURNS TABLE(problem_id text, best integer, total integer, all_pass boolean)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select s.problem_id, max(s.passed), max(s.total), bool_or(s.all_pass)
  from private.submissions s
  where s.code = upper(trim(p_code))
  group by s.problem_id;
$function$;

CREATE OR REPLACE FUNCTION public.my_record(p_code text)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select case when st.code is null then null else jsonb_build_object(
    'alias', st.alias,
    'problems', coalesce((
      select jsonb_agg(row_to_json(t)) from (
        select problem_id,
          count(*) as attempts,
          bool_or(all_pass) as ever_pass,
          max(passed) as best,
          max(total) as total,
          min(created_at) filter (where all_pass) as first_pass_at,
          max(created_at) as last_at
        from private.submissions where code = st.code
        group by problem_id) t), '[]'::jsonb)) end
  from (select 1) one left join private.students st on st.code = upper(trim(p_code));
$function$;

CREATE OR REPLACE FUNCTION public.my_solution(p_code text, p_problem text)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select jsonb_build_object('source', source, 'at', created_at)
  from private.submissions
  where code = upper(trim(p_code)) and problem_id = p_problem and all_pass
  order by created_at desc limit 1;
$function$;

CREATE OR REPLACE FUNCTION public.ranking_top3()
 RETURNS TABLE(place integer, alias text, solved integer, reached_at timestamp with time zone)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  with fp as (
    select code, problem_id, min(created_at) as t
    from private.submissions where all_pass group by code, problem_id
  ), per as (
    select code, count(*)::int as solved, max(t) as reached_at from fp group by code
  )
  select (row_number() over (order by per.solved desc, per.reached_at asc))::int,
         coalesce(st.alias, '이름 없는 학생'), per.solved, per.reached_at
  from per join private.students st on st.code = per.code
  order by 1 limit 3;
$function$;

CREATE OR REPLACE FUNCTION public.set_alias(p_code text, p_alias text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  c text := upper(trim(p_code));
  a text := regexp_replace(trim(coalesce(p_alias, '')), '\s+', ' ', 'g');
  squeezed text;
  last timestamptz;
  bad text[] := array['시발','씨발','씨바','ㅅㅂ','ㅆㅂ','병신','ㅂㅅ','븅신','개새','개색','새끼','존나','졸라','좆','지랄','ㅈㄹ','미친','닥쳐','꺼져','섹스','야동','느금','니애미','애미','애비','fuck','shit','bitch','sex','porn'];
  w text;
begin
  select alias_changed_at into last from private.students where code = c;
  if not found then return 'nocode'; end if;
  if char_length(a) < 2 or char_length(a) > 10 then return 'len'; end if;
  if a !~ '^[가-힣A-Za-z0-9 ]+$' then return 'chars'; end if;
  squeezed := lower(replace(a, ' ', ''));
  foreach w in array bad loop
    if position(w in squeezed) > 0 then return 'banned'; end if;
  end loop;
  if last is not null and last > now() - interval '10 minutes' then return 'wait'; end if;
  -- 다른 학생이 지금 쓰거나 원래 받은 별명은 쓸 수 없음
  if exists (select 1 from private.students
             where code <> c and (lower(alias) = lower(a) or lower(default_alias) = lower(a))) then
    return 'taken';
  end if;
  update private.students set alias = a, alias_changed_at = now() where code = c;
  return 'ok';
exception when unique_violation then
  return 'taken';
end;
$function$;

CREATE OR REPLACE FUNCTION public.submit_result(p_code text, p_problem text, p_passed integer, p_total integer, p_cases jsonb, p_source text)
 RETURNS boolean
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare c text := upper(trim(p_code));
begin
  if not exists (select 1 from private.students where code = c) then return false; end if;
  if (select count(*) from private.submissions
        where code = c and created_at > now() - interval '1 minute') >= 40 then
    return false;
  end if;
  if length(coalesce(p_cases::text, '')) > 30000 then p_cases := '[]'::jsonb; end if;
  insert into private.submissions (code, problem_id, passed, total, cases, source)
  values (c, p_problem, p_passed, p_total, coalesce(p_cases, '[]'::jsonb), left(coalesce(p_source, ''), 20000));
  return true;
end;
$function$;

CREATE OR REPLACE FUNCTION public.teacher_login(p_key text)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select private.teacher_ok(p_key);
$function$;

CREATE OR REPLACE FUNCTION public.teacher_history(p_key text, p_code text, p_since timestamp with time zone DEFAULT NULL::timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
  if not private.teacher_ok(p_key) then raise exception 'bad key' using errcode = '28000'; end if;
  return (
    select coalesce(jsonb_agg(row_to_json(t) order by t.created_at desc), '[]'::jsonb) from (
      select id, problem_id, passed, total, all_pass, cases, source, created_at
      from private.submissions
      where code = upper(trim(p_code)) and created_at >= coalesce(p_since, '-infinity'::timestamptz)
      order by created_at desc limit 300
    ) t);
end;
$function$;

CREATE OR REPLACE FUNCTION public.teacher_overview(p_key text, p_since timestamp with time zone DEFAULT NULL::timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare since timestamptz := coalesce(p_since, '-infinity'::timestamptz);
begin
  if not private.teacher_ok(p_key) then raise exception 'bad key' using errcode = '28000'; end if;
  return jsonb_build_object(
    'now', now(),
    'students', (
      select coalesce(jsonb_agg(row_to_json(t) order by t.code), '[]'::jsonb) from (
        select st.code, st.alias,
          count(su.id)                                         as submits,
          count(distinct su.problem_id)                        as tried,
          count(distinct su.problem_id) filter (where su.all_pass) as solved,
          max(su.created_at)                                   as last_at,
          (array_agg(su.problem_id order by su.created_at desc))[1] as last_problem,
          (array_agg(su.all_pass  order by su.created_at desc))[1] as last_pass
        from private.students st
        left join private.submissions su on su.code = st.code and su.created_at >= since
        group by st.code, st.alias
      ) t),
    'problems', (
      select coalesce(jsonb_agg(row_to_json(t)), '[]'::jsonb) from (
        select problem_id,
          count(distinct code)                         as tried,
          count(distinct code) filter (where all_pass) as solved,
          count(*)                                     as submits
        from private.submissions where created_at >= since
        group by problem_id
      ) t),
    'feed', (
      select coalesce(jsonb_agg(row_to_json(t)), '[]'::jsonb) from (
        select id, code, problem_id, passed, total, created_at
        from private.submissions where created_at >= since
        order by created_at desc limit 30
      ) t)
  );
end;
$function$;

CREATE OR REPLACE FUNCTION public.teacher_reset_alias(p_key text, p_code text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r text;
begin
  if not private.teacher_ok(p_key) then raise exception 'bad key' using errcode = '28000'; end if;
  update private.students set alias = default_alias, alias_changed_at = null
  where code = upper(trim(p_code)) returning alias into r;
  return r;
end;
$function$;

CREATE OR REPLACE FUNCTION public.teacher_save_problems(p_key text, p_problems jsonb, p_version integer)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare cur int; nv int; p jsonb; ids text[] := '{}';
begin
  if not private.teacher_ok(p_key) then raise exception 'bad key' using errcode = '28000'; end if;
  select version into cur from private.problem_set where id = 1 for update;
  if coalesce(cur, 0) <> coalesce(p_version, 0) then
    return jsonb_build_object('ok', false, 'reason', 'conflict', 'version', coalesce(cur, 0));
  end if;
  if jsonb_typeof(p_problems) <> 'array' or jsonb_array_length(p_problems) > 1000 then
    return jsonb_build_object('ok', false, 'reason', 'invalid', 'version', coalesce(cur, 0));
  end if;
  if octet_length(p_problems::text) > 3000000 then
    return jsonb_build_object('ok', false, 'reason', 'too_big', 'version', coalesce(cur, 0));
  end if;
  for p in select * from jsonb_array_elements(p_problems) loop
    if jsonb_typeof(p) <> 'object' or coalesce(p->>'id', '') = '' or length(p->>'id') > 64
       or jsonb_typeof(p->'tests') is distinct from 'array' or (p->>'id') = any(ids) then
      return jsonb_build_object('ok', false, 'reason', 'invalid', 'version', coalesce(cur, 0));
    end if;
    ids := ids || (p->>'id');
  end loop;
  if cur is not null then
    insert into private.problem_set_history (data, version) select data, version from private.problem_set where id = 1;
    delete from private.problem_set_history where id not in (select id from private.problem_set_history order by id desc limit 30);
  end if;
  nv := coalesce(cur, 0) + 1;
  insert into private.problem_set (id, data, version, updated_at) values (1, p_problems, nv, now())
  on conflict (id) do update set data = excluded.data, version = excluded.version, updated_at = excluded.updated_at;
  return jsonb_build_object('ok', true, 'version', nv);
end;
$function$;

CREATE OR REPLACE FUNCTION public.teacher_student(p_key text, p_code text, p_since timestamp with time zone DEFAULT NULL::timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare c text := upper(trim(p_code));
begin
  if not private.teacher_ok(p_key) then raise exception 'bad key' using errcode = '28000'; end if;
  return (
    select coalesce(jsonb_agg(row_to_json(t) order by t.last_at desc), '[]'::jsonb) from (
      select l.*, ps.source as pass_source, ps.created_at as pass_at
      from (
        select distinct on (problem_id)
          problem_id, passed, total, all_pass, cases, source, created_at as last_at,
          count(*)      over (partition by problem_id) as attempts,
          bool_or(all_pass) over (partition by problem_id) as ever_pass
        from private.submissions
        where code = c and created_at >= coalesce(p_since, '-infinity'::timestamptz)
        order by problem_id, created_at desc
      ) l
      left join lateral (
        select s.source, s.created_at from private.submissions s
        where s.code = c and s.problem_id = l.problem_id and s.all_pass
        order by s.created_at desc limit 1
      ) ps on true
    ) t);
end;
$function$;

-- 교사 비밀번호 넣기 (SQL Editor에서 '새비밀번호'만 바꿔 실행):
-- insert into private.settings(k, v) values ('teacher_salt', encode(extensions.gen_random_bytes(16), 'hex'))
--   on conflict (k) do update set v = excluded.v;
-- insert into private.settings(k, v)
--   select 'teacher_hash', encode(extensions.digest(v || '새비밀번호', 'sha256'), 'hex') from private.settings where k = 'teacher_salt'
--   on conflict (k) do update set v = excluded.v;
