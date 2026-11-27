-- Миграция надёжности: UNIQUE, SECURITY DEFINER, least-privilege RLS, аудит отмен, restore RPC.
-- Применена к проекту vvdegrbjngcgxffqykvj. Идемпотентна (IF NOT EXISTS / DROP IF EXISTS где возможно).

-- 1. UNIQUE: один человек — один подарок, один подарок — одному человеку (последний рубеж)
CREATE UNIQUE INDEX IF NOT EXISTS handouts_one_per_person ON public.handouts (person_id);
CREATE UNIQUE INDEX IF NOT EXISTS handouts_one_per_gift   ON public.handouts (gift_id);

-- 2. Аудит отмен: вместо DELETE пишем копию в историю
CREATE TABLE IF NOT EXISTS public.handouts_history (
  id bigint NOT NULL,
  person_id bigint NOT NULL,
  gift_id bigint NOT NULL,
  gift_name text NOT NULL,
  person_name text NOT NULL,
  operator text,
  created_at timestamptz NOT NULL,
  cancelled_at timestamptz NOT NULL DEFAULT now(),
  cancelled_by text
);
ALTER TABLE public.handouts_history ENABLE ROW LEVEL SECURITY;
-- anon не имеет доступа к истории вообще (только через SECURITY DEFINER функции)
REVOKE ALL ON public.handouts_history FROM anon, authenticated;

-- 3. Триггеры-стражи: received/status меняются только из функций (владелец postgres)
CREATE OR REPLACE FUNCTION public.guard_people_received() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_user <> 'postgres'
     AND (NEW.received IS DISTINCT FROM OLD.received
          OR NEW.received_at IS DISTINCT FROM OLD.received_at) THEN
    RAISE EXCEPTION 'received/received_at can only be changed via assign_gift/unassign_handout';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_guard_people_received ON public.people;
CREATE TRIGGER trg_guard_people_received BEFORE UPDATE ON public.people
  FOR EACH ROW EXECUTE FUNCTION public.guard_people_received();

CREATE OR REPLACE FUNCTION public.guard_gifts_status() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF current_user <> 'postgres'
     AND (NEW.status IS DISTINCT FROM OLD.status
          OR NEW.given_to IS DISTINCT FROM OLD.given_to
          OR NEW.given_at IS DISTINCT FROM OLD.given_at) THEN
    RAISE EXCEPTION 'status/given_to/given_at can only be changed via assign_gift/unassign_handout';
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_guard_gifts_status ON public.gifts;
CREATE TRIGGER trg_guard_gifts_status BEFORE UPDATE ON public.gifts
  FOR EACH ROW EXECUTE FUNCTION public.guard_gifts_status();

-- 4. assign_gift: SECURITY DEFINER, каноническое имя подарка, валидация
CREATE OR REPLACE FUNCTION public.assign_gift(
  p_person_id bigint,
  p_gift_name text,
  p_operator text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_person people%ROWTYPE;
  v_gift_id bigint;
  v_gift_name text;
  v_now timestamptz := now();
BEGIN
  IF p_person_id IS NULL OR p_gift_name IS NULL OR trim(p_gift_name) = '' THEN
    RETURN jsonb_build_object('ok', false, 'error', 'invalid_input');
  END IF;
  SELECT * INTO v_person FROM people WHERE id = p_person_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'person_not_found');
  END IF;
  IF v_person.received THEN
    RETURN jsonb_build_object('ok', false, 'error', 'already_received',
      'person_name', v_person.full_name, 'received_at', v_person.received_at);
  END IF;

  SELECT id, name INTO v_gift_id, v_gift_name
  FROM gifts
  WHERE lower(name) = lower(trim(p_gift_name)) AND status = 'available'
  ORDER BY id
  FOR UPDATE SKIP LOCKED
  LIMIT 1;

  IF v_gift_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'no_gift_available', 'gift_name', p_gift_name);
  END IF;

  UPDATE gifts SET status = 'given', given_to = p_person_id, given_at = v_now WHERE id = v_gift_id;
  UPDATE people SET received = true, received_at = v_now WHERE id = v_person.id;
  INSERT INTO handouts (person_id, gift_id, gift_name, person_name, operator)
    VALUES (v_person.id, v_gift_id, v_gift_name, v_person.full_name, p_operator);

  RETURN jsonb_build_object('ok', true, 'gift_id', v_gift_id, 'gift_name', v_gift_name,
    'person_name', v_person.full_name, 'given_at', v_now);
END;
$$;

-- 5. unassign_handout: блокировки, проверки, аудит вместо потери истории
CREATE OR REPLACE FUNCTION public.unassign_handout(
  p_handout_id bigint
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_h handouts%ROWTYPE;
  v_gift gifts%ROWTYPE;
BEGIN
  SELECT * INTO v_h FROM handouts WHERE id = p_handout_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'handout_not_found');
  END IF;
  SELECT * INTO v_gift FROM gifts WHERE id = v_h.gift_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'handout_not_found');
  END IF;
  IF v_gift.status <> 'given' OR v_gift.given_to IS DISTINCT FROM v_h.person_id THEN
    RETURN jsonb_build_object('ok', false, 'error', 'inconsistent_state');
  END IF;
  PERFORM 1 FROM people WHERE id = v_h.person_id FOR UPDATE;
  INSERT INTO handouts_history (id, person_id, gift_id, gift_name, person_name, operator, created_at, cancelled_by)
    VALUES (v_h.id, v_h.person_id, v_h.gift_id, v_h.gift_name, v_h.person_name, v_h.operator, v_h.created_at, NULL);
  UPDATE gifts SET status = 'available', given_to = NULL, given_at = NULL WHERE id = v_h.gift_id;
  UPDATE people SET received = false, received_at = NULL WHERE id = v_h.person_id;
  DELETE FROM handouts WHERE id = v_h.id;
  RETURN jsonb_build_object('ok', true, 'person_id', v_h.person_id, 'gift_id', v_h.gift_id);
END;
$$;

-- 6. update_person_contact: только телефон/комментарий, без возможности тронуть received
CREATE OR REPLACE FUNCTION public.update_person_contact(
  p_person_id bigint,
  p_phone text DEFAULT NULL,
  p_comment text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
  IF p_person_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'invalid_input');
  END IF;
  UPDATE people SET phone = nullif(trim(p_phone), ''), comment = nullif(trim(p_comment), '')
  WHERE id = p_person_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'person_not_found');
  END IF;
  RETURN jsonb_build_object('ok', true);
END;
$$;

-- 7. restore_backup: атомарная замена всех данных из JSON-бэкапа с сохранением ID
CREATE OR REPLACE FUNCTION public.restore_backup(
  p_people jsonb DEFAULT '[]'::jsonb,
  p_gifts jsonb DEFAULT '[]'::jsonb,
  p_handouts jsonb DEFAULT '[]'::jsonb
) RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_people int := 0;
  v_gifts int := 0;
  v_handouts int := 0;
BEGIN
  DELETE FROM handouts;
  DELETE FROM gifts;
  DELETE FROM people;

  IF p_people IS NOT NULL AND jsonb_array_length(p_people) > 0 THEN
    INSERT INTO people (id, full_name, phone, member_number, received, received_at, comment, created_at)
    OVERRIDING SYSTEM VALUE
    SELECT id, full_name, phone, member_number, received, received_at, comment, created_at
    FROM jsonb_populate_recordset(null::people, p_people);
    GET DIAGNOSTICS v_people = ROW_COUNT;
  END IF;

  IF p_gifts IS NOT NULL AND jsonb_array_length(p_gifts) > 0 THEN
    INSERT INTO gifts (id, slot_number, name, status, given_to, given_at, created_at)
    OVERRIDING SYSTEM VALUE
    SELECT id, slot_number, name, status, given_to, given_at, created_at
    FROM jsonb_populate_recordset(null::gifts, p_gifts);
    GET DIAGNOSTICS v_gifts = ROW_COUNT;
  END IF;

  IF p_handouts IS NOT NULL AND jsonb_array_length(p_handouts) > 0 THEN
    INSERT INTO handouts (id, person_id, gift_id, gift_name, person_name, operator, created_at)
    OVERRIDING SYSTEM VALUE
    SELECT id, person_id, gift_id, gift_name, person_name, operator, created_at
    FROM jsonb_populate_recordset(null::handouts, p_handouts);
    GET DIAGNOSTICS v_handouts = ROW_COUNT;
  END IF;

  PERFORM setval('people_id_seq', COALESCE((SELECT max(id) FROM people), 1));
  PERFORM setval('gifts_id_seq', COALESCE((SELECT max(id) FROM gifts), 1));
  PERFORM setval('handouts_id_seq', COALESCE((SELECT max(id) FROM handouts), 1));

  RETURN jsonb_build_object('ok', true, 'people', v_people, 'gifts', v_gifts, 'handouts', v_handouts);
END;
$$;

-- 8. Least-privilege политики: SELECT всем, INSERT людям/подаркам, DELETE только неполучившим
DROP POLICY IF EXISTS anon_all_people ON public.people;
DROP POLICY IF EXISTS anon_select_people ON public.people;
DROP POLICY IF EXISTS anon_insert_people ON public.people;
DROP POLICY IF EXISTS anon_update_people ON public.people;
DROP POLICY IF EXISTS anon_delete_people ON public.people;
CREATE POLICY anon_select_people ON public.people FOR SELECT TO anon USING (true);
CREATE POLICY anon_insert_people ON public.people FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY anon_update_people ON public.people FOR UPDATE TO anon USING (true) WITH CHECK (true);
CREATE POLICY anon_delete_people ON public.people FOR DELETE TO anon USING (received = false);

DROP POLICY IF EXISTS anon_all_gifts ON public.gifts;
DROP POLICY IF EXISTS anon_select_gifts ON public.gifts;
DROP POLICY IF EXISTS anon_insert_gifts ON public.gifts;
CREATE POLICY anon_select_gifts ON public.gifts FOR SELECT TO anon USING (true);
CREATE POLICY anon_insert_gifts ON public.gifts FOR INSERT TO anon WITH CHECK (true);

DROP POLICY IF EXISTS anon_all_handouts ON public.handouts;
DROP POLICY IF EXISTS anon_select_handouts ON public.handouts;
CREATE POLICY anon_select_handouts ON public.handouts FOR SELECT TO anon USING (true);

-- 9. Гранты: убрать прямую запись в handouts/gifts-статусы
REVOKE INSERT, UPDATE, DELETE ON public.handouts FROM anon;
REVOKE UPDATE, DELETE ON public.gifts FROM anon;
GRANT SELECT ON public.handouts TO anon;
GRANT SELECT, INSERT ON public.gifts TO anon;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.people TO anon;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon;

GRANT EXECUTE ON FUNCTION public.assign_gift(bigint, text, text) TO anon;
GRANT EXECUTE ON FUNCTION public.unassign_handout(bigint) TO anon;
GRANT EXECUTE ON FUNCTION public.update_person_contact(bigint, text, text) TO anon;
GRANT EXECUTE ON FUNCTION public.restore_backup(jsonb, jsonb, jsonb) TO anon;
