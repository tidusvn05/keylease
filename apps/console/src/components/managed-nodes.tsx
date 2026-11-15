import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api/client";
import type { components } from "@/lib/api/schema";

type Rule = components["schemas"]["ManagedRule"];

/** Nodes that joined the organization and the signed rules they apply (owners and admins). */
export function ManagedNodes({ org }: { org: string }) {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const key = ["managed-nodes", org];
  const { data } = useQuery({
    queryKey: key,
    queryFn: async () => (await api.GET("/v1/orgs/{org}/nodes", { params: { path: { org } } })).data ?? null,
    refetchInterval: 30_000,
  });
  const [command, setCommand] = useState<string | null>(null);
  const [draft, setDraft] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const rulesText = draft ?? JSON.stringify(data?.policy.rules ?? [], null, 2);
  const time = (value?: string | null) => (value ? new Date(value).toLocaleString(i18n.language) : "—");

  const enroll = async () => {
    const { data: created } = await api.POST("/v1/orgs/{org}/nodes/enrollments", { params: { path: { org } } });
    setCommand(created?.command ?? null);
  };
  const save = async () => {
    let rules: Rule[];
    try {
      rules = JSON.parse(rulesText) as Rule[];
    } catch {
      setMessage(t("nodes.invalidJson"));
      return;
    }
    const { data: saved, error } = await api.PUT("/v1/orgs/{org}/node-policy", {
      params: { path: { org } },
      body: { rules },
    });
    setMessage(error ? t("nodes.saveFailed") : t("nodes.saved", { version: saved?.version ?? 0 }));
    if (!error) setDraft(null);
    await queryClient.invalidateQueries({ queryKey: key });
  };
  const remove = async (member: string) => {
    await api.DELETE("/v1/orgs/{org}/nodes/{member}", { params: { path: { org, member } } });
    await queryClient.invalidateQueries({ queryKey: key });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("nodes.title")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">{t("nodes.help")}</p>
        {(data?.nodes ?? []).map((node) => (
          <div key={node.member_id} className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{node.name}</span>
            <Badge variant={node.applied_version === data?.policy.version ? "secondary" : "outline"}>
              {node.applied_version == null
                ? t("nodes.noPolicy")
                : t("nodes.applied", { version: node.applied_version })}
            </Badge>
            <span className="text-muted-foreground text-xs">{t("nodes.lastSeen", { time: time(node.last_seen_at) })}</span>
            <Button size="sm" variant="ghost" onClick={() => void remove(node.member_id)}>
              {t("orgs.remove")}
            </Button>
          </div>
        ))}
        <Button size="sm" variant="outline" onClick={() => void enroll()}>
          {t("nodes.enroll")}
        </Button>
        {command && (
          <div className="space-y-1">
            <p>{t("nodes.enrollHelp")}</p>
            <code className="bg-muted block rounded p-2 font-mono text-xs break-all">{command}</code>
          </div>
        )}
        <div className="space-y-1">
          <label className="block font-medium" htmlFor={`rules-${org}`}>
            {t("nodes.rules", { version: data?.policy.version ?? 0 })}
          </label>
          <p className="text-muted-foreground text-xs">{t("nodes.rulesHelp")}</p>
          <textarea
            id={`rules-${org}`}
            className="border-input bg-background min-h-40 w-full rounded-md border p-2 font-mono text-xs"
            value={rulesText}
            onChange={(event) => setDraft(event.target.value)}
            spellCheck={false}
          />
          <Button size="sm" onClick={() => void save()}>
            {t("nodes.sign")}
          </Button>
          {message && <p role="status">{message}</p>}
        </div>
      </CardContent>
    </Card>
  );
}
