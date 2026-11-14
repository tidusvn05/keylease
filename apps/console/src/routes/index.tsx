import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { ServerStatus } from "@/components/server-status";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export const Route = createFileRoute("/")({
  component: Overview,
});

function Overview() {
  const { t } = useTranslation();
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold tracking-tight">{t("overview.title")}</h1>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("app.name")}</CardTitle>
          <CardDescription>{t("overview.intro")}</CardDescription>
        </CardHeader>
        <CardContent>
          <ServerStatus />
        </CardContent>
      </Card>
    </div>
  );
}
