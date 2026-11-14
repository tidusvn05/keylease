import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { KeyRound } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api/client";
import { ssoStartUrl } from "@/lib/paths";
import { meQuery, passkeysQuery, ssoQuery } from "@/lib/queries";
import { registerPasskey } from "@/lib/session";

export const Route = createFileRoute("/passkeys")({
  component: Passkeys,
});

function Passkeys() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const { data: me } = useQuery(meQuery);
  const { data: passkeys = [] } = useQuery(passkeysQuery);
  const [failed, setFailed] = useState(false);
  const { data: sso } = useQuery(ssoQuery);
  const { data: identities = [] } = useQuery({
    queryKey: ["sso-identities"],
    enabled: sso?.enabled === true,
    queryFn: async () => (await api.GET("/v1/console/sso/identities")).data?.identities ?? [],
  });
  const unlink = useMutation({
    mutationFn: (subject: string) =>
      api.DELETE("/v1/console/sso/identities/{subject}", { params: { path: { subject } } }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["sso-identities"] }),
  });
  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: ["passkeys"] }),
      queryClient.invalidateQueries({ queryKey: ["me"] }),
    ]);
  const add = useMutation({
    mutationFn: () => registerPasskey(t("passkeys.defaultName")),
    onSuccess: (ok) => setFailed(!ok),
    onError: () => setFailed(true),
    onSettled: refresh,
  });
  const remove = useMutation({
    mutationFn: async (credential: string) => {
      await api.DELETE("/v1/console/passkeys/{credential}", {
        params: { path: { credential } },
      });
    },
    onSettled: refresh,
  });
  const date = (value: string | null | undefined) =>
    value ? new Date(value).toLocaleString(i18n.language) : t("passkeys.never");

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("passkeys.title")}</h1>
        <p className="text-muted-foreground">{t("passkeys.description")}</p>
      </div>
      {me?.passkeys_available === false ? (
        <p className="text-muted-foreground text-sm">{t("passkeys.unavailable")}</p>
      ) : (
        <Button onClick={() => add.mutate()} disabled={add.isPending}>
          <KeyRound className="size-4" aria-hidden />
          {t("passkeys.add")}
        </Button>
      )}
      {failed && (
        <p role="alert" className="text-destructive text-sm">
          {t("passkeys.failed")}
        </p>
      )}
      <div className="space-y-2">
        {passkeys.map((passkey) => (
          <Card key={passkey.credential_id}>
            <CardHeader className="flex flex-row items-center justify-between gap-4">
              <div>
                <CardTitle className="text-base">{passkey.name}</CardTitle>
                <CardDescription>
                  {t("passkeys.lastUsed")}: {date(passkey.last_used_at)}
                </CardDescription>
              </div>
              <Button
                size="sm"
                variant="outline"
                disabled={remove.isPending}
                onClick={() => remove.mutate(passkey.credential_id)}
              >
                {t("passkeys.remove")}
              </Button>
            </CardHeader>
          </Card>
        ))}
      </div>
      {sso?.enabled && (
        <div className="space-y-2">
          <h2 className="text-lg font-semibold">{t("passkeys.sso")}</h2>
          {identities.length === 0 && <p className="text-muted-foreground text-sm">{t("passkeys.ssoNone")}</p>}
          {identities.map((identity) => (
            <div key={identity.subject} className="flex items-center gap-2 text-sm">
              <span>{identity.email ?? identity.subject}</span>
              <Button size="sm" variant="ghost" onClick={() => unlink.mutate(identity.subject)}>
                {t("passkeys.ssoUnlink")}
              </Button>
            </div>
          ))}
          <Button asChild variant="outline">
            <a href={ssoStartUrl(true)}>{t("passkeys.ssoLink")}</a>
          </Button>
        </div>
      )}
    </div>
  );
}
