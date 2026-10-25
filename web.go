package main

import (
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

// web serves the approval and registration pages. WebAuthn needs HTTPS, so
// a TLS-terminating proxy sits in front of it.
type web struct {
	approvals *approvals
	keys      ceremony

	mu   sync.Mutex
	regs map[string]*webauthn.SessionData // registration token -> challenge
}

func newWeb(a *approvals, keys ceremony) *web {
	return &web{approvals: a, keys: keys, regs: map[string]*webauthn.SessionData{}}
}

func (w *web) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /approve/{id}", w.approvePage)
	mux.HandleFunc("POST /approve/{id}/options", w.approveOptions)
	mux.HandleFunc("POST /approve/{id}/verify", w.approveVerify)
	mux.HandleFunc("POST /approve/{id}/deny", w.deny)
	mux.HandleFunc("GET /register", w.registerPage)
	mux.HandleFunc("POST /register/options", w.registerOptions)
	mux.HandleFunc("POST /register/verify", w.registerVerify)
	return mux
}

func writeJSON(rw http.ResponseWriter, code int, v any) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(code)
	json.NewEncoder(rw).Encode(v)
}

func (w *web) approvePage(rw http.ResponseWriter, r *http.Request) {
	c, args, st, ok := w.approvals.view(r.PathValue("id"))
	if !ok {
		rw.WriteHeader(http.StatusNotFound)
		pages.ExecuteTemplate(rw, "gone", nil)
		return
	}
	pages.ExecuteTemplate(rw, "approve", struct {
		Client  string
		Command string
		State   string
		Pending bool
		Cached  bool
	}{c.String(), "op " + quoteArgs(args), st.String(), st == pending, st == approvedAndCached})
}

func (w *web) approveOptions(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	assertion, session, err := w.keys.beginLogin()
	if errors.Is(err, errNoPasskeys) {
		writeJSON(rw, http.StatusPreconditionFailed, map[string]string{"error": "No passkeys are registered. Register one at /register first."})
		return
	}
	if err != nil {
		slog.Error("starting passkey login", "request_id", id, "err", err)
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "couldn't start the passkey check"})
		return
	}
	if err := w.approvals.setSession(id, session); err != nil {
		writeJSON(rw, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, assertion)
}

func (w *web) approveVerify(rw http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx, span := tracer.Start(r.Context(), "passkey.verify")
	defer span.End()
	span.SetAttributes(attribute.String("op_gate.request_id", id))

	session, ok := w.approvals.takeSession(id)
	if !ok {
		writeJSON(rw, http.StatusConflict, map[string]string{"error": "This request has no open passkey check. Reload the page."})
		return
	}
	if err := w.keys.finishLogin(*session, r.WithContext(ctx)); err != nil {
		span.SetStatus(codes.Error, "passkey rejected")
		slog.WarnContext(ctx, "passkey check failed", "request_id", id, "err", err)
		writeJSON(rw, http.StatusForbidden, map[string]string{"error": "The passkey check failed."})
		return
	}
	to := approved
	if r.URL.Query().Get("remember") == "1" {
		to = approvedAndCached
	}
	st, err := w.approvals.decide(id, to)
	if err != nil {
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	span.SetAttributes(attribute.String("op_gate.outcome", st.String()))
	writeJSON(rw, http.StatusOK, map[string]string{"state": st.String()})
}

// deny needs no passkey: denying can't release anything.
func (w *web) deny(rw http.ResponseWriter, r *http.Request) {
	st, err := w.approvals.decide(r.PathValue("id"), denied)
	if err != nil {
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]string{"state": st.String()})
}

func (w *web) registerPage(rw http.ResponseWriter, _ *http.Request) {
	pages.ExecuteTemplate(rw, "register", nil)
}

// registerOptions is open to anyone who can reach the page. That's safe:
// a registration only produces a line of text, which does nothing until the
// operator adds it to the passkeys directory.
func (w *web) registerOptions(rw http.ResponseWriter, _ *http.Request) {
	creation, session, err := w.keys.beginRegistration()
	if err != nil {
		slog.Error("starting passkey registration", "err", err)
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": "couldn't start registration"})
		return
	}
	token := newID()
	w.mu.Lock()
	w.regs[token] = session
	w.mu.Unlock()
	time.AfterFunc(5*time.Minute, func() { w.takeRegistration(token) })
	writeJSON(rw, http.StatusOK, map[string]any{"token": token, "options": creation})
}

func (w *web) takeRegistration(token string) (*webauthn.SessionData, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.regs[token]
	delete(w.regs, token)
	return s, ok
}

func (w *web) registerVerify(rw http.ResponseWriter, r *http.Request) {
	session, ok := w.takeRegistration(r.URL.Query().Get("token"))
	if !ok {
		writeJSON(rw, http.StatusConflict, map[string]string{"error": "This registration expired. Reload the page."})
		return
	}
	cred, err := w.keys.finishRegistration(*session, r)
	if err != nil {
		slog.Warn("passkey registration failed", "err", err)
		writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "Registration failed."})
		return
	}
	line, err := json.Marshal(cred)
	if err != nil {
		writeJSON(rw, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(rw, http.StatusOK, map[string]string{"credential": string(line)})
}

// pages holds the approval and registration pages. The script converts
// between WebAuthn's ArrayBuffers and go-webauthn's base64url JSON by hand,
// so it doesn't depend on Safari's newer JSON helpers.
var pages = template.Must(template.New("").Parse(`
{{define "head"}}<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>op-gate</title>
<style>
 body{font:17px -apple-system,system-ui,sans-serif;margin:0 auto;max-width:34rem;padding:1.5rem;color:#111;background:#fafafa}
 @media(prefers-color-scheme:dark){body{color:#eee;background:#111}code,textarea{background:#222!important;color:#eee}}
 code{display:block;padding:.8rem;background:#eee;border-radius:.5rem;word-break:break-all}
 button{font:inherit;width:100%;padding:.9rem;margin:.4rem 0;border:0;border-radius:.6rem;color:#fff;background:#0a7}
 button.deny{background:#c33} button.cache{color:#0a7;background:none;box-shadow:inset 0 0 0 2px #0a7}
 .hint{font-size:14px;opacity:.7;margin:0 0 .8rem} textarea{width:100%;height:9rem;font:13px ui-monospace,monospace}
 #msg{min-height:1.5rem;margin-top:1rem}
</style>
<script>
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)).buffer;
const post = async (url, body) => {
  const r = await fetch(url, {method: 'POST', body: body && JSON.stringify(body)});
  const j = await r.json();
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
};
const say = t => { document.getElementById('msg').textContent = t; };
</script>{{end}}

{{define "gone"}}{{template "head"}}<h1>op-gate</h1><p>This request is unknown or has expired.</p>{{end}}

{{define "approve"}}{{template "head"}}<h1>op-gate</h1>
<p>{{.Client}} wants to run:</p><code>{{.Command}}</code>
{{if .Pending}}
<button onclick="approve()">Approve with Face ID</button>
<button class="cache" onclick="approve(true)">Approve and cache for 1 hour</button>
<p class="hint">op-gate runs this exact command again without asking, until it goes unused for 5 minutes or an hour passes.</p>
<button class="deny" onclick="deny()">Deny</button>
<p id="msg"></p>
<script>
const base = location.pathname;
async function approve(remember) {
  try {
    const opts = (await post(base + '/options')).publicKey;
    opts.challenge = unb64u(opts.challenge);
    (opts.allowCredentials || []).forEach(c => c.id = unb64u(c.id));
    const cred = await navigator.credentials.get({publicKey: opts});
    const res = cred.response;
    const out = await post(base + '/verify' + (remember ? '?remember=1' : ''), {
      id: cred.id, rawId: b64u(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: b64u(res.clientDataJSON), authenticatorData: b64u(res.authenticatorData),
        signature: b64u(res.signature), userHandle: res.userHandle && b64u(res.userHandle),
      },
    });
    say('Request ' + out.state + '.'); setTimeout(() => location.reload(), 800);
  } catch (e) { say(e.message); }
}
async function deny() {
  try { const out = await post(base + '/deny'); say('Request ' + out.state + '.'); setTimeout(() => location.reload(), 800); }
  catch (e) { say(e.message); }
}
</script>
{{else}}<p>This request is <strong>{{.State}}</strong>.{{if .Cached}} op-gate will run this exact command again without asking for up to an hour.{{end}}</p>{{end}}
{{end}}

{{define "register"}}{{template "head"}}<h1>Register a passkey</h1>
<p>This creates a passkey for op-gate on this device. Add the line it shows to op-gate's passkeys directory
as a new file named for this device (lowercase, no spaces). op-gate accepts the passkey after its next start.</p>
<button onclick="register()">Create passkey</button>
<p id="msg"></p><textarea id="out" readonly hidden></textarea>
<script>
async function register() {
  try {
    const {token, options} = await post('/register/options');
    const opts = options.publicKey;
    opts.challenge = unb64u(opts.challenge);
    opts.user.id = unb64u(opts.user.id);
    (opts.excludeCredentials || []).forEach(c => c.id = unb64u(c.id));
    const cred = await navigator.credentials.create({publicKey: opts});
    const res = cred.response;
    const out = await post('/register/verify?token=' + token, {
      id: cred.id, rawId: b64u(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: b64u(res.clientDataJSON), attestationObject: b64u(res.attestationObject),
        transports: res.getTransports ? res.getTransports() : [],
      },
    });
    const box = document.getElementById('out');
    box.value = out.credential; box.hidden = false; box.select();
    say('Copy this line into 1Password.');
  } catch (e) { say(e.message); }
}
</script>
{{end}}
`))
