import { AlertCircle, Loader2, LogIn } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api } from "../api";
import { Button } from "../components/ui/Button";
import { brand, Logo } from "@brand";

/** The dashboard's own sign-in page, shown in place of the app until there's a session. */
export function LoginPage({ onSignedIn, expired }: { onSignedIn: (user: string | null) => void; expired?: boolean }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { user } = await api.signIn(username, password);
      onSignedIn(user);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Couldn't sign in.");
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-bg flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-[380px] animate-in">
        <div className="flex flex-col items-center text-center mb-6">
          <Logo variant="full" height={36} title={brand.company} />
          <div className="text-[13px] text-fg-muted mt-3 font-medium">Firewall Best Practice Assessment</div>
        </div>
        <form
          onSubmit={submit}
          className="bg-surface border border-line rounded-xl shadow-card p-6 flex flex-col gap-4"
          aria-labelledby="sign-in-heading"
        >
          <div>
            <h1 id="sign-in-heading" className="text-[17px] font-semibold text-fg m-0">Sign in</h1>
            {expired && !error && (
              <p className="text-[12px] text-fg-muted mt-1 mb-0">Your session ended. Sign in again to carry on.</p>
            )}
          </div>
          <label className="flex flex-col gap-1.5 text-[12px] font-medium text-fg-2">
            Username
            <input
              type="text"
              name="username"
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full h-9"
            />
          </label>
          <label className="flex flex-col gap-1.5 text-[12px] font-medium text-fg-2">
            Password
            <input
              type="password"
              name="password"
              autoComplete="current-password"
              required
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full h-9"
            />
          </label>
          {error && (
            <p role="alert" className="flex items-start gap-1.5 text-[12px] text-critical-fg m-0">
              <AlertCircle size={14} className="mt-[1px] shrink-0" aria-hidden />
              {error}
            </p>
          )}
          <Button type="submit" variant="primary" className="h-9 w-full" disabled={busy}>
            {busy ? <Loader2 size={15} className="animate-spin" aria-hidden /> : <LogIn size={15} aria-hidden />}
            {busy ? "Signing in…" : "Sign in"}
          </Button>
        </form>
        <p className="text-[12px] text-fg-faint text-center mt-4 mb-0">
          Installed with the installer? The password is in pa-bpa-login.txt in the install folder.
        </p>
      </div>
    </div>
  );
}
