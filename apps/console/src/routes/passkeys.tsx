import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { KeyRound } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api/client";
import { meQuery, passkeysQuery } from "@/lib/queries";
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
    </div>
  );
}
