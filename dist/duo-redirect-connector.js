// Duo Universal Prompt redirect target, the same protocol as Bitwarden's
// apps/web/src/connectors/duo-redirect.ts. Duo sends the user back here with code and
// state; this page hands them to the client that started the login, which then sends
// "<code>|<state>" as the two-factor token.
const DUO_HOST_PATTERN = /^api-[a-zA-Z0-9]+\.(duosecurity|duofederal)\.com$/;
const MOBILE_DESKTOP_CALLBACK = 'bitwarden://duo-callback';

// The browser extension opens this page with ?duoFramelessUrl=<AuthUrl>. Only a Duo
// authorize URL may be followed, so the page cannot be used as an open redirect.
export function validateDuoFramelessUrl(value) {
  const url = new URL(value);
  if (url.username || url.password) throw new Error('Invalid Duo URL');
  if (url.protocol !== 'https:') throw new Error('Invalid Duo URL');
  if (url.port && url.port !== '443') throw new Error('Invalid Duo URL');
  if (url.pathname !== '/oauth/v1/authorize') throw new Error('Invalid Duo URL');
  if (!DUO_HOST_PATTERN.test(url.hostname)) throw new Error('Invalid Duo URL');
  return url.toString();
}

export function resolveDuoAction(search) {
  const params = new URLSearchParams(search);
  const framelessUrl = params.get('duoFramelessUrl');
  if (framelessUrl) return { kind: 'redirect', url: validateDuoFramelessUrl(framelessUrl) };
  const client = params.get('client');
  const code = params.get('code');
  const state = params.get('state');
  if (!client || !code || !state) throw new Error('Missing Duo response');
  if (client === 'web') return { kind: 'broadcast', code, state };
  if (client === 'browser') return { kind: 'postMessage', code, state };
  if (client === 'mobile' || client === 'desktop') {
    return {
      kind: 'redirect',
      url: `${MOBILE_DESKTOP_CALLBACK}?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
      showMessage: client === 'desktop',
    };
  }
  throw new Error('Unsupported Duo client');
}

function showMessage(text) {
  const message = document.getElementById('message');
  if (message) message.textContent = text;
}

function run() {
  let action;
  try {
    action = resolveDuoAction(window.location.search);
  } catch (error) {
    showMessage(error instanceof Error ? error.message : 'Duo login failed');
    return;
  }
  if (action.kind === 'broadcast') {
    const channel = new BroadcastChannel('duoResult');
    channel.postMessage({ code: action.code, state: action.state });
    channel.close();
    showMessage('Duo login complete. You may close this window.');
  } else if (action.kind === 'postMessage') {
    window.postMessage({ command: 'duoResult', code: action.code, state: action.state }, window.location.origin);
    showMessage('Duo login complete. You may close this window.');
  } else {
    if (action.showMessage) showMessage('Duo login complete. You may close this window.');
    window.location.replace(action.url);
  }
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  window.addEventListener('load', run);
}
