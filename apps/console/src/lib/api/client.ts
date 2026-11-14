import createClient from "openapi-fetch";
import { apiPrefix } from "@/lib/paths";
import type { paths } from "./schema";

// Same origin as the console. The session is an HttpOnly cookie; every request
// carries the header the server requires against cross-site requests.
export const api = createClient<paths>({
  baseUrl: window.location.origin + apiPrefix(),
  credentials: "same-origin",
  headers: { "x-keylease-console": "1" },
  // Look up fetch per call so tests (and wrappers) can replace it.
  fetch: (request) => globalThis.fetch(request),
});
