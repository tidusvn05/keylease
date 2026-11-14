import { useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { loginToken, ssoStartUrl } from "@/lib/paths";
import { ssoQuery } from "@/lib/queries";
import { exchangeLoginToken, signInWithPasskey } from "@/lib/session";

export function SignIn() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data: sso } = useQuery(ssoQuery);
  const [unlinked] = useState(() => window.location.hash === "#sso=unlinked");
  const [state, setState] = useState<"idle" | "busy" | "failed">(
    loginToken() === null ? "idle" : "busy",
  );

  const done = async (ok: boolean) => {
    if (ok) {
      await queryClient.invalidateQueries({ queryKey: ["me"] });
    } else {
      setState("failed");
    }
  };

  useEffect(() => {
    const token = loginToken();
    if (token !== null) {
      void exchangeLoginToken(token).then(done, () => setState("failed"));
    }
    // Runs once: the token is single use.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const passkey = () => {
    setState("busy");
    signInWithPasskey().then(done, () => setState("failed"));
  };

  return (
    <div className="flex min-h-svh items-center justify-center px-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>{t("signIn.title")}</CardTitle>
          <CardDescription>{t("signIn.deviceLink")}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Button className="w-full" onClick={passkey} disabled={state === "busy"}>
            <KeyRound className="size-4" aria-hidden />
            {state === "busy" ? t("signIn.signingIn") : t("signIn.passkey")}
          </Button>
          {sso?.enabled && (
            <Button asChild variant="outline" className="w-full">
              <a href={ssoStartUrl()}>{t("signIn.sso")}</a>
            </Button>
          )}
          {unlinked && (
            <p role="alert" className="text-sm">
              {t("signIn.ssoUnlinked")}
            </p>
          )}
          {state === "failed" && (
            <p role="alert" className="text-destructive text-sm">
              {t("signIn.failed")}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
