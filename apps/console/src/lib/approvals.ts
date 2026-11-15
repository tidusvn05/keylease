import { startAuthentication } from "@simplewebauthn/browser";
import { api } from "@/lib/api/client";
import type { components } from "@/lib/api/schema";

export type TrustDecision = components["schemas"]["TrustDecision"];

/**
 * Decides one pending approval of a node. The server builds the decision from
 * the node's latest report; a passkey signs it here, and the node checks that
 * signature again before applying it.
 */
export async function decideApproval(
  memberId: string,
  approvalId: string,
  approve: boolean,
  trust?: TrustDecision,
): Promise<string> {
  const { data: options, error } = await api.POST("/v1/console/approvals/challenge", {
    body: { member_id: memberId, approval_id: approvalId, approve, trust },
  });
  if (options === undefined) throw new Error(errorText(error));
  const credential = await startAuthentication({
    optionsJSON: {
      challenge: options.challenge,
      rpId: options.rp_id,
      allowCredentials: options.allow_credentials.map((id) => ({ id, type: "public-key" })),
      userVerification: "required",
      timeout: 60_000,
    },
  });
  const { data, error: decideError } = await api.POST("/v1/console/approvals/decide", {
    body: {
      payload: options.payload,
      assertion: {
        credential_id: credential.id,
        client_data_json: credential.response.clientDataJSON,
        authenticator_data: credential.response.authenticatorData,
        signature: credential.response.signature,
      },
    },
  });
  if (data === undefined) throw new Error(errorText(decideError));
  return data.decision_id;
}

/** The server's error code (`denied`, `invalid_request`, …). */
function errorText(error: unknown): string {
  if (typeof error === "object" && error !== null && "error" in error) {
    return String((error as { error: unknown }).error);
  }
  return "unknown";
}
