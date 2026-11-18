-- Run this SQL in your Supabase Project -> SQL Editor
-- Safely creates or updates studio_users, studio_config, and studio_history with full persistence.

CREATE TABLE IF NOT EXISTS public.studio_users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  email TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT 'user',
  created_by TEXT NOT NULL DEFAULT 'rajuadmin',
  pic_limit INTEGER NOT NULL DEFAULT 100,
  voice_limit INTEGER NOT NULL DEFAULT 30,
  video_limit INTEGER NOT NULL DEFAULT 10,
  pics_used INTEGER NOT NULL DEFAULT 0,
  voices_used INTEGER NOT NULL DEFAULT 0,
  videos_used INTEGER NOT NULL DEFAULT 0,
  allow_master_api BOOLEAN NOT NULL DEFAULT TRUE,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  expires_at TIMESTAMPTZ NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- If upgrading an existing studio_users table from an earlier version:
ALTER TABLE public.studio_users ADD COLUMN IF NOT EXISTS video_limit INTEGER NOT NULL DEFAULT 10;
ALTER TABLE public.studio_users ADD COLUMN IF NOT EXISTS videos_used INTEGER NOT NULL DEFAULT 0;
ALTER TABLE public.studio_users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE public.studio_users ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NULL;
ALTER TABLE public.studio_users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TABLE IF NOT EXISTS public.studio_config (
  id INTEGER PRIMARY KEY,
  model_cfg JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.studio_history (
  id TEXT PRIMARY KEY,
  user_id UUID NOT NULL,
  kind TEXT NOT NULL,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_studio_history_user_kind ON public.studio_history (user_id, kind, created_at DESC);

-- Lock down browser access: only your Express server (via SUPABASE_SERVICE_ROLE_KEY) can read/write.
ALTER TABLE public.studio_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.studio_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.studio_history ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Enable all access for studio" ON public.studio_users;
DROP POLICY IF EXISTS "Enable all access for studio_config" ON public.studio_config;
DROP POLICY IF EXISTS "Enable all access for studio_history" ON public.studio_history;
