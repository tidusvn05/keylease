import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api/client";
import { orgsQuery } from "@/lib/queries";

/** MCP Gateway calls waiting for a project admin, across the person's organizations. */
export function GatewayApprovals() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const { data: orgs = [] } = useQuery(orgsQuery);
  const results = useQueries({
    queries: orgs.map((org) => ({
      queryKey: ["gateway-approvals", org.org_id],
      queryFn: async () => {
        const { data } = await api.GET("/v1/orgs/{org}/gateway/approvals", {
          params: { path: { org: org.org_id } },
        });
        return data?.approvals ?? [];
      },
      refetchInterval: 5_000,
    })),
  });
  const [busy, setBusy] = useState<string | null>(null);
  const rows = orgs.flatMap((org, index) =>
    (results[index]?.data ?? []).map((approval) => ({ org, approval })),
  );
  if (rows.length === 0) return null;
  const time = (value: string) => new Date(value).toLocaleString(i18n.language);
  const decide = async (org: string, approval: string, approve: boolean) => {
    setBusy(approval);
    try {
      await api.POST("/v1/orgs/{org}/gateway/approvals/{approval}", {
        params: { path: { org, approval } },
        body: { approve },
      });
    } finally {
      setBusy(null);
      await queryClient.invalidateQueries({ queryKey: ["gateway-approvals", org] });
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("approvals.gateway")}</CardTitle>
        <CardDescription>{t("approvals.gatewayHelp")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {rows.map(({ org, approval }) => (
          <div key={approval.approval_id} className="space-y-2 rounded-md border p-3 text-sm">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <span className="font-medium">
                <span className="font-mono">
                  {approval.method} {approval.binding}
                  {approval.path}
                </span>
                {approval.body_bytes > 0 && (
                  <span className="text-muted-foreground ml-2 text-xs">
                    {t("approvals.bodyBytes", { count: approval.body_bytes })}
                  </span>
                )}
              </span>
              <Badge variant={approval.state === "pending" ? "secondary" : "outline"}>
                {t(`approvals.gatewayStates.${approval.state}`)}
              </Badge>
            </div>
            <p className="text-muted-foreground">
              {t("approvals.gatewayWho", {
                client: approval.client,
                org: org.name,
                project: approval.project,
                environment: approval.environment,
                time: time(approval.created_at),
              })}
            </p>
            {approval.state === "pending" && (
              <div className="flex gap-2">
                <Button
                  size="sm"
                  disabled={busy === approval.approval_id}
                  onClick={() => void decide(org.org_id, approval.approval_id, true)}
                >
                  {t("approvals.approve")}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy === approval.approval_id}
                  onClick={() => void decide(org.org_id, approval.approval_id, false)}
                >
                  {t("approvals.deny")}
                </Button>
              </div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
