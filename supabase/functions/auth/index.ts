import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

const usernamePattern = /^[A-Za-z0-9_-]{3,24}$/;
const internalEmailDomain = 'auth.enchat.internal';

type AuthRequest = {
  action?: 'signup' | 'login';
  username?: string;
  password?: string;
};

function response(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  });
}

function normalizeUsername(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const username = value.trim().toLowerCase();
  return usernamePattern.test(username) ? username : null;
}

function validPassword(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 8 && value.length <= 128;
}

function genericAuthError(): Response {
  return response({ error: 'Invalid username or password.' }, 401);
}

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  if (request.method !== 'POST') {
    return response({ error: 'Method not allowed.' }, 405);
  }

  const supabaseUrl = Deno.env.get('SUPABASE_URL');
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY');

  if (!supabaseUrl || !serviceRoleKey || !anonKey) {
    return response({ error: 'Authentication service is not configured.' }, 500);
  }

  let payload: AuthRequest;
  try {
    payload = await request.json();
  } catch {
    return genericAuthError();
  }

  const username = normalizeUsername(payload.username);
  if (!username || !validPassword(payload.password)) {
    return genericAuthError();
  }

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
  const publicClient = createClient(supabaseUrl, anonKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  if (payload.action === 'signup') {
    const { data: existingProfile, error: existingProfileError } = await admin
      .from('profiles')
      .select('id')
      .ilike('username', username)
      .maybeSingle();

    if (existingProfileError) {
      return response({ error: 'Authentication service unavailable.' }, 503);
    }

    if (existingProfile) {
      return genericAuthError();
    }

    // This internal identity never leaves the function or appears in the UI.
    const internalEmail = `${crypto.randomUUID()}@${internalEmailDomain}`;
    const { data: createdUser, error: createUserError } = await admin.auth.admin.createUser({
      email: internalEmail,
      password: payload.password,
      email_confirm: true,
      user_metadata: { enchat_username: username },
    });

    if (createUserError || !createdUser.user) {
      return genericAuthError();
    }

    const { error: profileError } = await admin.from('profiles').upsert(
      { id: createdUser.user.id, username },
      { onConflict: 'id' },
    );

    if (profileError) {
      await admin.auth.admin.deleteUser(createdUser.user.id);
      return response({ error: 'Authentication service unavailable.' }, 503);
    }

    const { data: sessionData, error: sessionError } = await publicClient.auth.signInWithPassword({
      email: internalEmail,
      password: payload.password,
    });

    if (sessionError || !sessionData.session) {
      return response({ error: 'Authentication service unavailable.' }, 503);
    }

    return response({ session: sessionData.session, user: { id: createdUser.user.id, username } });
  }

  if (payload.action === 'login') {
    const { data: profile, error: profileError } = await admin
      .from('profiles')
      .select('id, username')
      .ilike('username', username)
      .maybeSingle();

    if (profileError || !profile) {
      return genericAuthError();
    }

    const { data: authUserData, error: authUserError } = await admin.auth.admin.getUserById(profile.id);
    const internalEmail = authUserData.user?.email;

    if (authUserError || !internalEmail) {
      return genericAuthError();
    }

    const { data: sessionData, error: sessionError } = await publicClient.auth.signInWithPassword({
      email: internalEmail,
      password: payload.password,
    });

    if (sessionError || !sessionData.session) {
      return genericAuthError();
    }

    await admin
      .from('profiles')
      .update({ username })
      .eq('id', profile.id);

    return response({ session: sessionData.session, user: { id: profile.id, username } });
  }

  return genericAuthError();
});
