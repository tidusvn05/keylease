import createClient from "openapi-fetch";
import type { paths } from "./schema";

// Same-origin: the console is served by keylease-server, and Vite proxies the
// API in development. Cookies carry the session; no token is kept in JS.
export const api = createClient<paths>({
  baseUrl: window.location.origin,
  credentials: "same-origin",
  // Look up fetch per call so tests (and wrappers) can replace it.
  fetch: (request) => globalThis.fetch(request),
});
