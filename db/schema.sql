-- Схема изолированного проекта Supabase для раздачи подарков (одно мероприятие).
-- Применяется через Supabase migration. Не затрагивает другие проекты.

CREATE TABLE IF NOT EXISTS public.people (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  full_name text NOT NULL,
  phone text,
  member_number text,
  received boolean NOT NULL DEFAULT false,
  received_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.gifts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  slot_number integer,
  name text NOT NULL,
  status text NOT NULL DEFAULT 'available' CHECK (status IN ('available','given')),
  given_to bigint REFERENCES public.people(id) ON DELETE SET NULL,
  given_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.handouts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  person_id bigint NOT NULL REFERENCES public.people(id) ON DELETE RESTRICT,
  gift_id bigint NOT NULL REFERENCES public.gifts(id) ON DELETE RESTRICT,
  gift_name text NOT NULL,
  person_name text NOT NULL,
  operator text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS people_lower_name_idx ON public.people (lower(full_name));
CREATE INDEX IF NOT EXISTS people_received_idx ON public.people (received);
CREATE UNIQUE INDEX IF NOT EXISTS people_member_number_idx ON public.people (member_number) WHERE member_number IS NOT NULL;
CREATE INDEX IF NOT EXISTS gifts_status_idx ON public.gifts (status);
CREATE INDEX IF NOT EXISTS gifts_lower_name_idx ON public.gifts (lower(name));
CREATE INDEX IF NOT EXISTS handouts_person_idx ON public.handouts (person_id);
CREATE INDEX IF NOT EXISTS handouts_created_idx ON public.handouts (created_at);

-- Row Level Security: внутренний инструмент мероприятия, доступ по anon-ключу из браузера.
ALTER TABLE public.people ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.gifts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.handouts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS anon_all_people ON public.people;
CREATE POLICY anon_all_people ON public.people FOR ALL TO anon USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS anon_all_gifts ON public.gifts;
CREATE POLICY anon_all_gifts ON public.gifts FOR ALL TO anon USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS anon_all_handouts ON public.handouts;
CREATE POLICY anon_all_handouts ON public.handouts FOR ALL TO anon USING (true) WITH CHECK (true);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.people, public.gifts, public.handouts TO anon;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon;

-- Атомарная выдача: один подарок — одному человеку. Защита от двойной выдачи
-- и от конфликтов между несколькими операторами (блокировки строк + проверка статуса).
CREATE OR REPLACE FUNCTION public.assign_gift(
  p_person_id bigint,
  p_gift_name text,
  p_operator text DEFAULT NULL
) RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
  v_person people%ROWTYPE;
  v_gift_id bigint;
  v_now timestamptz := now();
BEGIN
  SELECT * INTO v_person FROM people WHERE id = p_person_id FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'person_not_found');
  END IF;
  IF v_person.received THEN
    RETURN jsonb_build_object('ok', false, 'error', 'already_received',
      'person_name', v_person.full_name, 'received_at', v_person.received_at);
  END IF;

  SELECT id INTO v_gift_id
  FROM gifts
  WHERE lower(name) = lower(p_gift_name) AND status = 'available'
  ORDER BY id
  FOR UPDATE SKIP LOCKED
  LIMIT 1;

  IF v_gift_id IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'error', 'no_gift_available', 'gift_name', p_gift_name);
  END IF;

  UPDATE gifts SET status = 'given', given_to = p_person_id, given_at = v_now WHERE id = v_gift_id;
  UPDATE people SET received = true, received_at = v_now WHERE id = v_person.id;
  INSERT INTO handouts (person_id, gift_id, gift_name, person_name, operator)
    VALUES (v_person.id, v_gift_id, p_gift_name, v_person.full_name, p_operator);

  RETURN jsonb_build_object('ok', true, 'gift_id', v_gift_id, 'gift_name', p_gift_name,
    'person_name', v_person.full_name, 'given_at', v_now);
END;
$$;

-- Отмена выдачи (исправление ошибок).
CREATE OR REPLACE FUNCTION public.unassign_handout(
  p_handout_id bigint
) RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
  v_person_id bigint;
  v_gift_id bigint;
BEGIN
  SELECT person_id, gift_id INTO v_person_id, v_gift_id FROM handouts WHERE id = p_handout_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('ok', false, 'error', 'handout_not_found');
  END IF;
  UPDATE gifts SET status = 'available', given_to = NULL, given_at = NULL WHERE id = v_gift_id;
  UPDATE people SET received = false, received_at = NULL WHERE id = v_person_id;
  DELETE FROM handouts WHERE id = p_handout_id;
  RETURN jsonb_build_object('ok', true, 'person_id', v_person_id, 'gift_id', v_gift_id);
END;
$$;

GRANT EXECUTE ON FUNCTION public.assign_gift(bigint, text, text) TO anon;
GRANT EXECUTE ON FUNCTION public.unassign_handout(bigint) TO anon;

-- Realtime: трансляция изменений всем операторам.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    BEGIN ALTER PUBLICATION supabase_realtime ADD TABLE public.people; EXCEPTION WHEN duplicate_object THEN NULL; END;
    BEGIN ALTER PUBLICATION supabase_realtime ADD TABLE public.gifts; EXCEPTION WHEN duplicate_object THEN NULL; END;
    BEGIN ALTER PUBLICATION supabase_realtime ADD TABLE public.handouts; EXCEPTION WHEN duplicate_object THEN NULL; END;
  END IF;
END $$;
