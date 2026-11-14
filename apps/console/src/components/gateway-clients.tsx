import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api/client";

const input = "border-input bg-background h-9 rounded-md border px-3 text-sm";

/** MCP Gateway clients of an organization (owners and admins). */
export function GatewayClients({
  org,
  environments,
}: {
  org: string;
  environments: { project: string; environment: string }[];
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const key = ["gateway", org];
  const { data: clients = [] } = useQuery({
    queryKey: key,
    queryFn: async () =>
      (await api.GET("/v1/orgs/{org}/gateway/clients", { params: { path: { org } } })).data?.clients ?? [],
  });
  const [created, setCreated] = useState<{ token: string; url?: string | null } | null>(null);

  const create = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const grants = data
      .getAll("grant")
      .map((value) => String(value).split("/"))
      .map(([project, environment]) => ({ project: project ?? "", environment: environment ?? "" }));
    const { data: client } = await api.POST("/v1/orgs/{org}/gateway/clients", {
      params: { path: { org } },
      body: { name: String(data.get("name")), allow_writes: data.get("allow_writes") === "on", grants },
    });
    if (client) {
      setCreated({ token: client.token, url: client.url });
      form.reset();
    }
    await queryClient.invalidateQueries({ queryKey: key });
  };
  const revoke = async (client: string) => {
    await api.DELETE("/v1/orgs/{org}/gateway/clients/{client}", { params: { path: { org, client } } });
    await queryClient.invalidateQueries({ queryKey: key });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("orgs.gateway")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">{t("orgs.gatewayHelp")}</p>
        {clients.map((client) => (
          <div key={client.client_id} className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{client.name}</span>
            <span className="text-muted-foreground">
              {client.grants.map((grant) => `${grant.project}/${grant.environment}`).join(", ")}
            </span>
            <Button size="sm" variant="ghost" onClick={() => void revoke(client.client_id)}>
              {t("orgs.remove")}
            </Button>
          </div>
        ))}
        {created && (
          <div className="space-y-1">
            <p>{t("orgs.clientToken")}</p>
            <code className="bg-muted block rounded p-2 font-mono text-xs break-all">
              {`claude mcp add --transport http keylease ${created.url ?? "<server>/v1/orgs/" + org + "/mcp"} --header "Authorization: Bearer ${created.token}"`}
            </code>
          </div>
        )}
        <form className="space-y-2" onSubmit={(event) => void create(event)}>
          <input className={input} name="name" required placeholder={t("orgs.clientName")} aria-label={t("orgs.clientName")} />
          <div className="flex flex-wrap gap-3">
            {environments.map(({ project, environment }) => (
              <label key={`${project}/${environment}`} className="flex items-center gap-1">
                <input type="checkbox" name="grant" value={`${project}/${environment}`} />
                {project}/{environment}
              </label>
            ))}
          </div>
          <label className="flex items-center gap-1">
            <input type="checkbox" name="allow_writes" />
            {t("orgs.allowWrites")}
          </label>
          <Button type="submit" size="sm">
            {t("orgs.createClient")}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
