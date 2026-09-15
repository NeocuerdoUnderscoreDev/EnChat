import { useEffect, useMemo, useState } from 'react';
import { decryptMessage, encryptMessage } from './crypto/encryption';
import { generateChatKey, getOrCreateUserKey, loadChatKey, storeChatKey, unwrapChatKey, wrapChatKey } from './crypto/keyStore';
import { supabase } from './lib/supabase';

type View = 'landing' | 'auth' | 'dashboard' | 'chat';
type AuthMode = 'signup' | 'login';
type Chat = { id: string; chat_code: string; created_by: string; created_at: string };
type Message = { id: string; chat_id: string; sender_id: string; ciphertext: string; nonce: string; created_at: string; plaintext?: string };
type Profile = { id: string; username: string };

export default function App() {
  const [view, setView] = useState<View>('landing');
  const [authMode, setAuthMode] = useState<AuthMode>('signup');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [profile, setProfile] = useState<Profile | null>(null);
  const [chats, setChats] = useState<Chat[]>([]);
  const [activeChat, setActiveChat] = useState<Chat | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [compose, setCompose] = useState('');
  const [joinCode, setJoinCode] = useState('');
  const [showJoin, setShowJoin] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [loading, setLoading] = useState(false);

  const isLoggedIn = useMemo(() => Boolean(profile), [profile]);

  const loadProfile = async (userId: string) => {
    const { data, error: profileError } = await supabase.from('profiles').select('id, username').eq('id', userId).single();
    if (profileError) throw profileError;
    setProfile(data as Profile);
    const deviceKey = await getOrCreateUserKey(userId);
    const { error: keyError } = await supabase.from('user_keys').upsert({ user_id: userId, public_key_jwk: deviceKey.publicKeyJwk }, { onConflict: 'user_id' });
    if (keyError) throw keyError;
  };

  const getChatKey = async (chatId: string): Promise<CryptoKey> => {
    if (!profile) throw new Error('Not authenticated.');
    const localKey = await loadChatKey(profile.id, chatId);
    if (localKey) return localKey;
    const { data, error: wrappedKeyError } = await supabase.from('wrapped_chat_keys').select('wrapped_key').eq('chat_id', chatId).eq('user_id', profile.id).single();
    if (wrappedKeyError) throw new Error('The chat key is not available yet. The other participant must be online.');
    const deviceKey = await getOrCreateUserKey(profile.id);
    const chatKey = await unwrapChatKey(data.wrapped_key, deviceKey.privateKey);
    await storeChatKey(profile.id, chatId, chatKey);
    return chatKey;
  };

  const provisionChatKey = async (chat: Chat, userId: string, publicKeyJwk: JsonWebKey, chatKey: CryptoKey) => {
    const wrappedKey = await wrapChatKey(chatKey, publicKeyJwk);
    const { error: keyError } = await supabase.rpc('add_wrapped_chat_key', { p_chat_id: chat.id, p_user_id: userId, p_wrapped_key: wrappedKey });
    if (keyError) throw keyError;
  };

  const loadChats = async () => {
    const { data, error: chatsError } = await supabase.from('chats').select('id, chat_code, created_by, created_at').is('destroyed_at', null).order('created_at', { ascending: false });
    if (chatsError) throw chatsError;
    setChats((data ?? []) as Chat[]);
  };

  useEffect(() => {
    let mounted = true;
    void supabase.auth.getSession().then(async ({ data }) => {
      if (!mounted || !data.session) return;
      try { await loadProfile(data.session.user.id); await loadChats(); if (mounted) setView('dashboard'); } catch { await supabase.auth.signOut(); }
    });
    const { data: listener } = supabase.auth.onAuthStateChange(async (_event, session) => {
      if (!mounted || !session) return;
      try { await loadProfile(session.user.id); await loadChats(); if (mounted) setView('dashboard'); } catch { setError('Session expired. Please log in again.'); }
    });
    return () => { mounted = false; listener.subscription.unsubscribe(); };
  }, []);

  const handleAuth = async () => {
    const normalized = username.trim().toLowerCase();
    if (!/^[a-z0-9_-]{3,24}$/.test(normalized) || password.length < 8 || password.length > 128 || (authMode === 'signup' && password !== confirmPassword)) {
      setError('Invalid username or password.'); return;
    }
    setLoading(true); setError('');
    try {
      const { data, error: functionError } = await supabase.functions.invoke('auth', { body: { action: authMode, username: normalized, password } });
      if (functionError || !data?.session) throw functionError ?? new Error('Invalid username or password.');
      const { error: sessionError } = await supabase.auth.setSession(data.session);
      if (sessionError) throw sessionError;
      await loadProfile(data.user.id); await loadChats();
      setPassword(''); setConfirmPassword(''); setView('dashboard');
    } catch (authError) { setError(authError instanceof Error ? authError.message : 'Invalid username or password.'); }
    finally { setLoading(false); }
  };

  const openChat = async (chat: Chat) => {
    if (!profile) return;
    setLoading(true); setError('');
    try {
      const { data, error: messagesError } = await supabase.from('messages').select('id, chat_id, sender_id, ciphertext, nonce, created_at').eq('chat_id', chat.id).order('created_at', { ascending: true });
      if (messagesError) throw messagesError;
      const key = await getChatKey(chat.id);
      const decrypted = await Promise.all((data ?? []).map(async (message) => ({ ...(message as Message), plaintext: await decryptMessage(message.ciphertext, message.nonce, key) })));
      setMessages(decrypted); setActiveChat(chat); setView('chat');
    } catch (chatError) { setActiveChat(chat); setMessages([]); setView('chat'); setError(chatError instanceof Error ? chatError.message : 'Could not load this chat.'); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    if (!activeChat || !profile) return;
    const channel = supabase.channel(`chat-${activeChat.id}`).on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'messages', filter: `chat_id=eq.${activeChat.id}` }, async (payload) => {
      const incoming = payload.new as Message;
      if (messages.some((message) => message.id === incoming.id)) return;
      const key = await getChatKey(activeChat.id);
      const plaintext = await decryptMessage(incoming.ciphertext, incoming.nonce, key);
      setMessages((current) => current.some((message) => message.id === incoming.id) ? current : [...current, { ...incoming, plaintext }]);
    }).on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'chat_members', filter: `chat_id=eq.${activeChat.id}` }, async (payload) => {
      const member = payload.new as { user_id: string; left_at: string | null };
      if (member.user_id === profile.id || member.left_at !== null || activeChat.created_by !== profile.id) return;
      try {
        const { data: members, error: memberError } = await supabase.rpc('get_chat_members', { p_chat_id: activeChat.id });
        if (memberError) throw memberError;
        const target = (members ?? []).find((item: { user_id: string }) => item.user_id === member.user_id) as { user_id: string; public_key_jwk: JsonWebKey } | undefined;
        if (!target) return;
        await provisionChatKey(activeChat, target.user_id, target.public_key_jwk, await getChatKey(activeChat.id));
      } catch (keyError) {
        setError(keyError instanceof Error ? keyError.message : 'Could not provision the chat key.');
      }
    }).on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'wrapped_chat_keys', filter: `chat_id=eq.${activeChat.id}` }, async (payload) => {
      const wrapped = payload.new as { user_id: string };
      if (wrapped.user_id === profile.id) await openChat(activeChat);
    }).subscribe();
    return () => { void supabase.removeChannel(channel); };
  }, [activeChat, profile, messages]);

  const createChat = async () => {
    setLoading(true); setError('');
    try { const { data, error: rpcError } = await supabase.rpc('create_chat'); if (rpcError) throw rpcError; const chat = data as Chat; const chatKey = await generateChatKey(); await storeChatKey(profile!.id, chat.id, chatKey); const deviceKey = await getOrCreateUserKey(profile!.id); await provisionChatKey(chat, profile!.id, deviceKey.publicKeyJwk, chatKey); setChats((current) => [chat, ...current]); await openChat(chat); }
    catch (chatError) { setError(chatError instanceof Error ? chatError.message : 'Could not create chat.'); }
    finally { setLoading(false); }
  };

  const joinChat = async () => {
    if (!/^\d{6}$/.test(joinCode)) { setError('Enter a valid 6-digit chat code.'); return; }
    setLoading(true); setError('');
    try { const { data, error: rpcError } = await supabase.rpc('join_chat', { p_chat_code: joinCode }); if (rpcError) throw rpcError; const chat = data as Chat; setChats((current) => current.some((item) => item.id === chat.id) ? current : [chat, ...current]); setJoinCode(''); setShowJoin(false); await openChat(chat); }
    catch (chatError) { setError(chatError instanceof Error ? chatError.message : 'Chat not found.'); }
    finally { setLoading(false); }
  };

  const sendMessage = async () => {
    if (!activeChat || !profile || !compose.trim()) return;
    const text = compose.trim(); setCompose('');
    try { const key = await getChatKey(activeChat.id); const encrypted = await encryptMessage(text, key); const { data, error: sendError } = await supabase.from('messages').insert({ chat_id: activeChat.id, sender_id: profile.id, ...encrypted }).select('id, chat_id, sender_id, ciphertext, nonce, created_at').single(); if (sendError) throw sendError; setMessages((current) => [...current, { ...(data as Message), plaintext: text }]); }
    catch (sendError) { setCompose(text); setError(sendError instanceof Error ? sendError.message : "Couldn't send that message. Try again."); }
  };

  const logout = async () => { await supabase.auth.signOut(); setProfile(null); setChats([]); setActiveChat(null); setMessages([]); setView('landing'); };
  const leaveChat = async () => { if (!activeChat) return; const { error: leaveError } = await supabase.rpc('leave_chat', { p_chat_id: activeChat.id }); if (leaveError) { setError(leaveError.message); return; } setChats((current) => current.filter((chat) => chat.id !== activeChat.id)); setActiveChat(null); setMessages([]); setView('dashboard'); };
  const destroyChat = async () => { if (!activeChat || !window.confirm('Destroy this chat? This action cannot be undone.')) return; const { error: destroyError } = await supabase.rpc('destroy_chat', { p_chat_id: activeChat.id }); if (destroyError) { setError(destroyError.message); return; } setChats((current) => current.filter((chat) => chat.id !== activeChat.id)); setActiveChat(null); setMessages([]); setShowSettings(false); setView('dashboard'); };
  const downloadChat = () => { if (!activeChat) return; const content = ['EnChat Conversation', '', `Chat Code: ${activeChat.chat_code}`, '', ...messages.map((message) => `${message.sender_id === profile?.id ? profile.username : 'participant'} — ${new Date(message.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}\n${message.plaintext ?? ''}`)].join('\n'); const url = URL.createObjectURL(new Blob([content], { type: 'text/plain;charset=utf-8' })); const anchor = document.createElement('a'); anchor.href = url; anchor.download = `enchat-${activeChat.chat_code}.txt`; anchor.click(); URL.revokeObjectURL(url); };

  const pageTitle =
    view === 'landing' ? 'EnChat' : view === 'dashboard' ? 'EnChat' : 'Private Chat';

  return (
    <div className="min-h-screen bg-paper text-ink">
      <div className="mx-auto flex min-h-screen max-w-5xl flex-col px-4 py-6 sm:px-6 lg:px-8">
        <header className="mb-8 flex items-center justify-between border-b border-line pb-4">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-muted">Private messaging</p>
            <h1 className="text-2xl font-semibold sm:text-3xl">{pageTitle}</h1>
          </div>
          {isLoggedIn && (
            <button
              type="button"
              className="rounded-xl border border-ink px-3 py-2 text-sm font-medium"
              onClick={() => void logout()}
            >
              Log Out
            </button>
          )}
        </header>

        {view === 'landing' && (
          <main className="flex flex-1 items-center justify-center">
            <section className="w-full max-w-xl rounded-2xl border border-line bg-white p-8 shadow-soft">
              <p className="mb-2 text-xs uppercase tracking-[0.2em] text-muted">EnChat</p>
              <h2 className="text-4xl font-semibold tracking-tight">Private messaging. Nothing else.</h2>
              <p className="mt-4 max-w-lg text-base text-muted">
                A simple private place to talk without feeds, servers, channels, or distractions.
              </p>
              <div className="mt-8 flex flex-col gap-3 sm:flex-row">
                <button
                  type="button"
                  className="rounded-xl bg-ink px-5 py-3 text-base font-medium text-white"
                  onClick={() => { setAuthMode('signup'); setView('auth'); setError(''); }}
                >
                  Create Account
                </button>
                <button
                  type="button"
                  className="rounded-xl border border-ink px-5 py-3 text-base font-medium"
                  onClick={() => { setAuthMode('login'); setView('auth'); setError(''); }}
                >
                  Log In
                </button>
              </div>
            </section>
          </main>
        )}

        {view === 'auth' && (
          <main className="mx-auto flex w-full max-w-md flex-1 items-center justify-center">
            <section className="w-full rounded-2xl border border-line bg-white p-6 shadow-soft">
              <h2 className="text-2xl font-semibold">{authMode === 'login' ? 'Log In' : 'Create Account'}</h2>
              <div className="mt-5 space-y-4">
                <label className="block text-sm font-medium">
                  Username
                  <input
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="mt-1 w-full border border-line bg-white px-3 py-2.5"
                    placeholder="alex"
                    aria-label="Username"
                  />
                </label>
                <label className="block text-sm font-medium">
                  Password
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="mt-1 w-full border border-line bg-white px-3 py-2.5"
                    placeholder="••••••••••"
                    aria-label="Password"
                  />
                </label>
                {authMode === 'signup' && (
                  <label className="block text-sm font-medium">
                    Confirm Password
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="mt-1 w-full border border-line bg-white px-3 py-2.5"
                      placeholder="••••••••••"
                      aria-label="Confirm password"
                    />
                  </label>
                )}
                {error && <p className="text-sm text-red-700">{error}</p>}
                <button
                  type="button"
                  className="w-full rounded-xl bg-ink px-4 py-3 text-base font-medium text-white"
                  onClick={() => void handleAuth()}
                >
                  {loading ? 'Please wait...' : authMode === 'login' ? 'Log In' : 'Create Account'}
                </button>
                <p className="text-center text-sm text-muted">
                  {authMode === 'signup' ? 'Already have an account? ' : "Don't have an account? "}
                  <button
                    type="button"
                    className="font-medium text-ink underline underline-offset-2"
                    onClick={() => {
                      setAuthMode(authMode === 'signup' ? 'login' : 'signup');
                      setError('');
                    }}
                  >
                    {authMode === 'signup' ? 'Log in.' : 'Create one.'}
                  </button>
                </p>
              </div>
            </section>
          </main>
        )}

        {view === 'dashboard' && (
          <main className="w-full max-w-4xl self-center">
            <div className="mb-6 flex items-center justify-between gap-4">
              <div>
                <p className="text-xs uppercase tracking-[0.2em] text-muted">EnChat</p>
                <h2 className="text-3xl font-semibold">Your Chats</h2>
              </div>
              <button type="button" className="rounded-xl border border-ink px-3 py-2 text-sm font-medium" onClick={() => void createChat()}>
                + New Chat
              </button>
            </div>

            <div className="rounded-2xl border border-line bg-white p-6 shadow-soft">
              <div className="mb-6 flex flex-col gap-3 sm:flex-row">
                <button type="button" className="rounded-xl bg-ink px-4 py-3 text-sm font-medium text-white" onClick={() => void createChat()}>
                  + New Chat
                </button>
                <button type="button" className="rounded-xl border border-ink px-4 py-3 text-sm font-medium" onClick={() => setShowJoin((value) => !value)}>
                  Join Chat
                </button>
              </div>
              {showJoin && <div className="mb-6 rounded-xl border border-line bg-paper p-4"><label className="block text-sm font-medium">Enter 6-digit chat code<input value={joinCode} onChange={(event) => setJoinCode(event.target.value.replace(/\D/g, '').slice(0, 6))} className="mt-2 w-full border border-line bg-white px-3 py-2.5" placeholder="000000" aria-label="Chat code" /></label><button type="button" className="mt-3 rounded-xl bg-ink px-4 py-2 text-sm font-medium text-white" onClick={() => void joinChat()}>Join Chat</button></div>}
              {error && <p className="mb-4 text-sm text-red-700">{error}</p>}
              {chats.length === 0 ? <div className="border-t border-line pt-6"><p className="text-lg font-medium">No conversations yet.</p><p className="mt-2 text-sm text-muted">Create a private chat or join one using a 6-digit code.</p></div> : <div className="space-y-3 border-t border-line pt-6">{chats.map((chat) => <button key={chat.id} type="button" className="flex w-full items-center justify-between rounded-xl border border-line bg-[#fafafa] p-4 text-left" onClick={() => void openChat(chat)}><div><p className="font-medium">Private chat</p><p className="text-sm text-muted">Code: {chat.chat_code}</p></div><span className="text-xs uppercase tracking-[0.2em] text-muted">Open</span></button>)}</div>}
            </div>
          </main>
        )}

        {view === 'chat' && activeChat && (
          <main className="mx-auto w-full max-w-3xl">
            <div className="mb-4 flex items-center justify-between gap-4 border-b border-line pb-4">
              <div className="flex items-center gap-3">
                <button type="button" className="rounded-xl border border-ink px-3 py-2 text-sm" onClick={() => setView('dashboard')}>
                  ← Back
                </button>
                <div>
                  <h2 className="text-xl font-semibold">Private chat</h2>
                  <p className="text-xs uppercase tracking-[0.2em] text-muted">Chat code: {activeChat.chat_code}</p>
                </div>
              </div>
              <button type="button" className="rounded-xl border border-ink px-3 py-2 text-sm" onClick={() => setShowSettings((value) => !value)}>
                Settings
              </button>
            </div>

            {showSettings && <div className="mb-4 rounded-xl border border-line bg-white p-4"><p className="text-lg font-semibold">Chat Settings</p><div className="mt-3 flex flex-wrap gap-2"><button type="button" className="rounded-xl border border-ink px-3 py-2 text-sm" onClick={() => void navigator.clipboard.writeText(activeChat.chat_code)}>Copy code</button><button type="button" className="rounded-xl border border-ink px-3 py-2 text-sm" onClick={downloadChat}>Download chat</button><button type="button" className="rounded-xl border border-ink px-3 py-2 text-sm" onClick={() => void leaveChat()}>Leave chat</button><button type="button" className="rounded-xl border border-red-700 px-3 py-2 text-sm text-red-700" onClick={() => void destroyChat()}>Destroy chat</button></div></div>}

            <section className="space-y-5 rounded-2xl border border-line bg-white p-4 shadow-soft">
              <div className="space-y-3 border-b border-line pb-4">
                {messages.length === 0 ? <div><p className="font-medium">Nothing here yet.</p><p className="mt-1 text-sm text-muted">Send the first message.</p></div> : messages.map((message) => <div key={message.id}><p className="font-medium">{message.sender_id === profile?.id ? profile.username : 'participant'}</p><p className="mt-1 text-sm">{message.plaintext}</p><p className="mt-1 text-[11px] uppercase tracking-[0.2em] text-muted">{new Date(message.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</p></div>)}
              </div>

              <div className="flex items-end gap-3">
                <textarea
                  rows={1}
                  className="min-h-[48px] flex-1 resize-none border border-line bg-[#fafafa] px-3 py-3"
                  value={compose}
                  onChange={(event) => setCompose(event.target.value)}
                  onKeyDown={(event) => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); void sendMessage(); } }}
                  placeholder="Write a message..."
                  aria-label="Write a message"
                />
                <button type="button" className="rounded-xl bg-ink px-4 py-3 text-sm font-medium text-white" onClick={() => void sendMessage()}>
                  Send
                </button>
              </div>
            </section>
          </main>
        )}
      </div>
    </div>
  );
}
