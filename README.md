# EnChat

EnChat is a minimal private messaging app built with React, TypeScript, Vite, Tailwind CSS, and Supabase. The goal is a private text-only communication experience without feeds, channels, public groups, or unnecessary social features.

## Philosophy

Private messaging. Nothing else.

## Features

- Username/password account creation and login
- Private chat room creation with a 6-digit human-readable code
- Join chat by code
- Real-time encrypted message exchange with Supabase Realtime
- Download and local export of chat history
- Leave chat and destroy chat flows
- Responsive monochrome UI
- Secure database rules via Supabase Row Level Security

## Stack

- React
- TypeScript
- Vite
- Tailwind CSS
- Supabase
- Vitest

## Setup

1. Install dependencies:
   npm install
2. Create a `.env` file from `.env.example` and fill in Supabase values:
   VITE_SUPABASE_URL=
   VITE_SUPABASE_ANON_KEY=
3. Run the app locally:
   npm run dev

## Supabase setup

Create a Supabase project and apply the SQL migrations in `supabase/migrations`.

### E2EE key management

Apply `supabase/migrations/002_e2ee_key_exchange.sql` after the initial schema. Each browser generates a persistent RSA-OAEP 3072-bit key pair with SHA-256 using Web Crypto. The private key is stored as a non-extractable `CryptoKey` in IndexedDB and is never sent to Supabase. The public JWK is stored in `user_keys`.

Each chat generates a random extractable 256-bit AES-GCM key in the browser. That key is wrapped separately with each participant's RSA-OAEP public key and stored only in `wrapped_chat_keys`; plaintext chat keys are never stored in Supabase. Messages continue to use a fresh 96-bit nonce for every AES-GCM encryption.

When a second participant joins, the chat owner receives the membership Realtime event, unwraps the locally stored chat key, wraps it for the new participant, and submits it through the owner-authorized `add_wrapped_chat_key` function. The joining browser receives only its own wrapped-key row and decrypts it with its local private key. Therefore the owner must be online at least once after the second participant joins for key provisioning to complete.

## Username/password Edge Function

The browser must never invent or submit an email address for EnChat authentication. The function at `supabase/functions/auth/index.ts` accepts only `{ action, username, password }`, normalizes and validates the username, keeps the internal Supabase Auth identity server-side, and returns a normal Supabase session. Passwords are passed to Supabase Auth over HTTPS and are never stored by EnChat.

The function uses these environment variables only inside the Edge Function runtime:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`

Supabase normally provides the first two project values to deployed functions. Set or verify them under **Edge Functions → Secrets** if your project does not provide them automatically. Add `SUPABASE_SERVICE_ROLE_KEY` there using the project’s service-role key. Never add that key to `.env`, `VITE_*` variables, frontend code, GitHub, or client requests.

Deploy from the project root with the Supabase CLI:

   supabase login
   supabase link --project-ref YOUR_PROJECT_REF
   supabase functions deploy auth --no-verify-jwt

The frontend should invoke the deployed function over HTTPS and pass the returned `session` to the existing Supabase browser client with `supabase.auth.setSession(session)`. The current UI is not modified by this backend addition.

### Supabase dashboard steps

1. Open **Project Settings → API** and copy the project reference, URL, anon key, and service-role key. Keep the service-role key private.
2. In **SQL Editor**, apply `supabase/migrations/001_initial_schema.sql` first.
3. In **Edge Functions**, deploy the `auth` function, or deploy it with the CLI command above.
4. In **Edge Functions → Secrets**, verify `SUPABASE_URL` and `SUPABASE_ANON_KEY`; add `SUPABASE_SERVICE_ROLE_KEY` as a secret.
5. In **Authentication → Providers**, keep Email enabled for the internal Auth identity. No email is requested from EnChat users.
6. In **Database → Publications**, verify `messages` and `chat_members` are included in `supabase_realtime`.
7. Test signup and login through the function URL. Do not test by sending an email field from the browser. The function must be public enough to receive unauthenticated login requests; it validates the request itself.

The internal Auth email is generated only inside the Edge Function because Supabase’s password verifier requires an email identity. It is never shown to or requested from the user, and the browser never generates it. Because a normal Supabase session includes the Auth user claims, the server-generated internal email can technically be present in the returned session JWT; it is not used as the user-facing identity. Do not display or log that claim.

## Security note

This project documents the intended encryption architecture: messages are encrypted in the browser before storage, while the backend stores only ciphertext and metadata. The browser decrypts locally for display. The app must not expose service-role keys or production secrets to the frontend.

## Privacy limitations

No system is perfectly private. Metadata such as timestamps, user IDs, chat membership, IP addresses, and server logs may remain visible to infrastructure providers or hosting services. Destroying a chat removes the active chat data but does not erase copies that exist outside your control.

## Deployment

The GitHub repository contains application source code and migration files; Supabase hosts the actual backend and database. Never commit `.env` files or service-role keys.
