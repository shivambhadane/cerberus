import { useId, useState } from "react";
import type { FormEvent } from "react";
import { ApiError, getMe, login, register } from "../api";
import {
  auth,
  createUserWithEmailAndPassword,
  formatFirebaseError,
  githubProvider,
  googleProvider,
  signInWithEmailAndPassword,
  signInWithPopup,
  updateProfile,
} from "../lib/firebase";
import type { User } from "../types";
import { Icon } from "./icons";
import { Banner } from "./ui";

type Mode = "login" | "register";

/**
 * Sign in or create an account via Firebase Authentication.
 * Styled matching the modern dual-panel aesthetic with warm diffuse gradient hero
 * and crisp credential controls.
 */
export function AuthGate({ onSignedIn, notice }: { onSignedIn: (user: User) => void; notice?: string }) {
  const id = useId();
  const [mode, setMode] = useState<Mode>("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const registering = mode === "register";

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!email.trim() || !password) return;
    setSubmitting(true);
    setError(null);

    try {
      if (registering && password.length < 6) {
        setError("Password is too weak. Use at least 6 characters (at least 5 characters required).");
        setPassword("");
        setSubmitting(false);
        return;
      }

      try {
        if (registering) {
          const cred = await createUserWithEmailAndPassword(auth, email.trim(), password);
          if (name.trim()) {
            await updateProfile(cred.user, { displayName: name.trim() }).catch(() => undefined);
          }
        } else {
          await signInWithEmailAndPassword(auth, email.trim(), password);
        }
        const me = await getMe();
        onSignedIn(me);
        return;
      } catch (fbErr) {
        const fbCode = fbErr && typeof fbErr === "object" && "code" in fbErr ? String(fbErr.code) : "";
        if (fbCode.startsWith("auth/")) {
          setError(formatFirebaseError(fbErr));
          setPassword("");
          return;
        }
        // Fallback to legacy local endpoint if Firebase connection was unreachable
        try {
          const result = registering
            ? await register(email, password, name)
            : await login(email, password);
          onSignedIn(result.user);
          return;
        } catch {
          throw fbErr;
        }
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : formatFirebaseError(e));
      setPassword("");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleGoogleSignIn() {
    setSubmitting(true);
    setError(null);
    try {
      await signInWithPopup(auth, googleProvider);
      const me = await getMe();
      onSignedIn(me);
    } catch (e) {
      setError(formatFirebaseError(e));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleGitHubSignIn() {
    setSubmitting(true);
    setError(null);
    try {
      await signInWithPopup(auth, githubProvider);
      const me = await getMe();
      onSignedIn(me);
    } catch (e) {
      setError(formatFirebaseError(e));
    } finally {
      setSubmitting(false);
    }
  }

  function switchMode() {
    setMode(registering ? "login" : "register");
    setError(null);
  }

  return (
    <div className="auth-container">
      {/* Left Column: Radiant Peach/Orange Gradient Hero */}
      <div className="auth-hero">
        <div className="auth-hero-top">
          <a href="/" className="auth-hero-brand" title="Back to Cerberus Website">
            <svg width="28" height="24" viewBox="0 0 40 42" fill="none" aria-hidden="true">
              <path d="M0 25C0 19.5 2.9 14.7 7.2 12C9.6 10.4 12.6 9.4 15.8 9.4V40.6C12.6 40.6 9.6 39.6 7.2 38C2.9 35.3 0 30.5 0 25Z" fill="#ff6426"/>
              <path d="M18.8 12C15.8 14.7 13.8 19.5 13.8 25C13.8 30.5 15.8 35.3 18.8 38C21.2 39.6 23.8 40.6 26.5 40.6V9.4C23.8 9.4 21.2 10.4 18.8 12Z" fill="#ff6426"/>
              <path d="M30 12C27.2 14.7 25.5 19.5 25.5 25C25.5 30.5 27.2 35.3 30 38C32.2 39.6 34.6 40.6 37.2 40.6V9.4C34.6 9.4 32.2 10.4 30 12Z" fill="#ff6426"/>
            </svg>
            <span>Cerberus</span>
          </a>
          <a
            href="/"
            className="auth-hero-pill"
            title="Return to Cerberus Website"
          >
            ← Website
          </a>
        </div>

        <div className="auth-hero-bottom">
          <span className="auth-hero-eyebrow">You can easily</span>
          <h2 className="auth-hero-headline">
            Get access your personal hub for clarity and productivity.
          </h2>
        </div>
      </div>

      {/* Right Column: Clean Form Credentials Card */}
      <form
        className="auth-form-panel"
        onSubmit={submit}
        aria-labelledby={`${id}-title`}
        noValidate
      >
        <div className="auth-star" aria-hidden="true">
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
            <path
              d="M12 2V22M2 12H22M4.93 4.93L19.07 19.07M4.93 19.07L19.07 4.93"
              stroke="#ff5e28"
              strokeWidth="3"
              strokeLinecap="round"
            />
          </svg>
        </div>

        <div className="auth-header">
          <h2 id={`${id}-title`}>
            {registering ? "Create your account" : "Sign in"}
          </h2>
          <p>
            {registering
              ? "Access your tasks, notes, and projects anytime, anywhere — and keep everything flowing in one place."
              : "Sign in to access your attack surface, verified domains, and findings."}
          </p>
        </div>

        {notice && <Banner tone="info" role="status">{notice}</Banner>}

        <div className="auth-fields">
          {registering && (
            <div>
              <label className="auth-label" htmlFor={`${id}-name`}>
                Full name (optional)
              </label>
              <input
                id={`${id}-name`}
                className="auth-input input"
                autoComplete="name"
                placeholder="Alex Morgan"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
          )}

          <div>
            <label className="auth-label" htmlFor={`${id}-email`}>
              Your email
            </label>
            <input
              id={`${id}-email`}
              className="auth-input input"
              type="email"
              autoComplete="email"
              inputMode="email"
              placeholder="natalia.brak@knmstudio.com"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div>
            <label className="auth-label" htmlFor={`${id}-password`}>
              {registering ? "Create password" : "Password"}
            </label>
            <div className="auth-password-box">
              <input
                id={`${id}-password`}
                className="auth-input input"
                type={showPassword ? "text" : "password"}
                autoComplete={registering ? "new-password" : "current-password"}
                placeholder="••••••••••••"
                required
                aria-describedby={registering ? `${id}-hint` : undefined}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button
                type="button"
                className="auth-password-eye"
                onClick={() => setShowPassword(!showPassword)}
                title={showPassword ? "Hide password" : "Show password"}
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                <Icon name={showPassword ? "eyeOff" : "eye"} />
              </button>
            </div>
            {registering && (
              <span id={`${id}-hint`} className="field-hint" style={{ marginTop: 4, display: "block" }}>
                At least 6 characters. A few unrelated words is easy to remember and hard to guess.
              </span>
            )}
          </div>
        </div>

        {error && <p role="alert" className="form-error">{error}</p>}

        <button
          type="submit"
          className="auth-btn-primary"
          disabled={submitting || !email.trim() || !password}
        >
          {submitting
            ? (registering ? "Creating account…" : "Signing in…")
            : (registering ? "Create account" : "Sign in")}
        </button>

        <div className="auth-sep">
          <span className="auth-sep-line" />
          <span className="auth-sep-text">or continue with</span>
          <span className="auth-sep-line" />
        </div>

        <div className="auth-social-row">
          <button
            type="button"
            className="auth-social-box"
            onClick={handleGoogleSignIn}
            title="Continue with Google"
            disabled={submitting}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
              <path
                fill="#4285F4"
                d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"
              />
              <path
                fill="#34A853"
                d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.25v3.15C3.26 21.36 7.34 24 12 24z"
              />
              <path
                fill="#FBBC05"
                d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.25C.45 8.18 0 10.04 0 12s.45 3.82 1.25 5.42l4.03-3.15z"
              />
              <path
                fill="#EA4335"
                d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.34 0 3.26 2.64 1.25 6.58l4.03 3.15c.95-2.83 3.6-4.98 6.72-4.98z"
              />
            </svg>
            <span>Google</span>
          </button>

          <button
            type="button"
            className="auth-social-box"
            onClick={handleGitHubSignIn}
            title="Continue with GitHub"
            disabled={submitting}
          >
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path
                fillRule="evenodd"
                clipRule="evenodd"
                d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
              />
            </svg>
            <span>GitHub</span>
          </button>
        </div>

        <p className="auth-footer-switch muted">
          {registering ? "Already have an account? " : "New to Cerberus? "}
          <button type="button" className="auth-switch-btn link-button" onClick={switchMode}>
            {registering ? "Sign in" : "Create an account"}
          </button>
        </p>

        <div className="auth-back-to-landing">
          <a href="/" title="Return to Cerberus website">
            ← Back to Cerberus Home
          </a>
        </div>
      </form>
    </div>
  );
}
