import { useQuery } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { ServerStatus } from "@/components/server-status";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { meQuery } from "@/lib/queries";

export const Route = createFileRoute("/")({
  component: Overview,
});

function Overview() {
  const { t } = useTranslation();
  const { data: me } = useQuery(meQuery);
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("overview.title")}</h1>
        <p className="text-muted-foreground">{t("overview.intro")}</p>
      </div>
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardDescription>{t("overview.account")}</CardDescription>
            <CardTitle className="truncate font-mono text-sm">{me?.account_id}</CardTitle>
          </CardHeader>
          <CardContent>
            <ServerStatus />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>{t("overview.ownerDevice")}</CardDescription>
            <CardTitle>{me?.owner_device ?? "—"}</CardTitle>
          </CardHeader>
          <CardContent>
            <Link to="/devices" className="text-sm underline">
              {t("nav.devices")}
            </Link>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>{t("overview.passkeys")}</CardDescription>
            <CardTitle>{me?.passkeys ?? 0}</CardTitle>
          </CardHeader>
          <CardContent>
            {me?.passkeys === 0 && (
              <p className="text-muted-foreground text-sm">{t("overview.noPasskeys")}</p>
            )}
            <Link to="/passkeys" className="text-sm underline">
              {t("nav.passkeys")}
            </Link>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
