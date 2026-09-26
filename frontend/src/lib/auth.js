/**
 * Sign-in session for the Netra UI.
 *
 * The access token lives in sessionStorage, so it is dropped when the tab closes.
 * Every call to the backend goes through `authorizedFetch`, which attaches the token
 * and sends the user back to the sign-in page when the session is rejected.
 */

const SESSION_KEY = 'netra.session';
const CHANGE_EVENT = 'netra-auth-change';

const gatewayBase = () => {
  if (process.env.NEXT_PUBLIC_GATEWAY_URL) return process.env.NEXT_PUBLIC_GATEWAY_URL;
  if (typeof window !== 'undefined') {
    return `${window.location.protocol}//${window.location.hostname || 'localhost'}:8080`;
  }
  return 'http://localhost:8080';
};

export function getSession() {
  if (typeof window === 'undefined') return null;
  try {
    const session = JSON.parse(window.sessionStorage.getItem(SESSION_KEY) || 'null');
    if (session?.token && session.expiresAt * 1000 > Date.now()) return session;
  } catch {
    /* unreadable storage counts as signed out */
  }
  return null;
}

function setSession(session) {
  try {
    if (session) window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
    else window.sessionStorage.removeItem(SESSION_KEY);
  } catch {
    /* storage blocked: the session lasts until reload */
  }
  window.dispatchEvent(new Event(CHANGE_EVENT));
}

export function onSessionChange(listener) {
  window.addEventListener(CHANGE_EVENT, listener);
  return () => window.removeEventListener(CHANGE_EVENT, listener);
}

/** Only same-site paths, so a crafted ?next= cannot send users elsewhere after sign-in. */
export function safeNextPath(next) {
  return typeof next === 'string' && next.startsWith('/') && !next.startsWith('//') ? next : '/';
}

export class SignInError extends Error {}

export async function signIn(username, password) {
  let res;
  try {
    res = await fetch(`${gatewayBase()}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
      signal: AbortSignal.timeout(10000),
    });
  } catch {
    throw new SignInError('Cannot reach the Netra gateway. Check that the pipeline is running.');
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new SignInError(body.detail || `Sign-in failed (HTTP ${res.status}).`);
  }
  const data = await res.json();
  const session = { token: data.access_token, username: data.username, role: data.role, expiresAt: data.expires_at };
  setSession(session);
  return session;
}

export function signOut() {
  setSession(null);
}

function redirectToSignIn() {
  if (typeof window === 'undefined' || window.location.pathname === '/login') return;
  const next = window.location.pathname + window.location.search;
  window.location.assign(`/login?next=${encodeURIComponent(next)}`);
}

/** fetch() with the session token; a rejected session signs the user out. */
export async function authorizedFetch(url, init = {}) {
  const session = getSession();
  if (!session) {
    redirectToSignIn();
    throw new SignInError('Sign in to continue.');
  }
  const headers = new Headers(init.headers || {});
  headers.set('Authorization', `Bearer ${session.token}`);
  const res = await fetch(url, { ...init, headers });
  if (res.status === 401) {
    signOut();
    redirectToSignIn();
  }
  return res;
}
