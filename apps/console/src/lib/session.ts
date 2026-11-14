import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { api } from "@/lib/api/client";

/** Exchanges a device link token once; the token is removed from the URL first. */
export async function exchangeLoginToken(token: string): Promise<boolean> {
  window.history.replaceState(null, "", window.location.pathname + window.location.search);
  const { response } = await api.POST("/v1/console/session", { body: { token } });
  return response.ok;
}

export async function signInWithPasskey(): Promise<boolean> {
  const { data: options } = await api.POST("/v1/console/passkeys/login/options");
  if (options === undefined) return false;
  // The server returns WebAuthn options in their JSON form.
  const credential = await startAuthentication({ optionsJSON: options as never });
  const { response } = await api.POST("/v1/console/passkeys/login", {
    body: {
      credential_id: credential.id,
      client_data_json: credential.response.clientDataJSON,
      authenticator_data: credential.response.authenticatorData,
      signature: credential.response.signature,
    },
  });
  return response.ok;
}

export async function registerPasskey(name: string): Promise<boolean> {
  const { data: options } = await api.POST("/v1/console/passkeys/register/options");
  if (options === undefined) return false;
  const credential = await startRegistration({ optionsJSON: options as never });
  const { response } = await api.POST("/v1/console/passkeys/register", {
    body: {
      client_data_json: credential.response.clientDataJSON,
      attestation_object: credential.response.attestationObject,
      name,
    },
  });
  return response.ok;
}

export async function signOut(): Promise<void> {
  await api.POST("/v1/console/logout");
}
