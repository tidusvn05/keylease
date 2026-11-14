/** Where the console is mounted: `/console`, or `/api/console` behind a proxy prefix. */
export function consoleBase(pathname: string = window.location.pathname): string {
  const index = pathname.indexOf("/console");
  // The Vite dev and preview servers serve the app at the root.
  return index < 0 ? "" : pathname.slice(0, index + "/console".length);
}

/** The server API prefix: whatever comes before `/console` (often empty or `/api`). */
export function apiPrefix(pathname: string = window.location.pathname): string {
  const base = consoleBase(pathname);
  return base === "" ? "" : base.slice(0, base.length - "/console".length);
}

/** The one-time sign-in token from a device link (`…/console/#login=TOKEN`). */
export function loginToken(hash: string = window.location.hash): string | null {
  const match = /^#login=([A-Za-z0-9_-]{16,128})$/.exec(hash);
  return match?.[1] ?? null;
}
