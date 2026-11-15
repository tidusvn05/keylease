import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api/client";

const input = "border-input bg-background h-9 rounded-md border px-3 text-sm";

type Auth = "none" | "bearer" | "oauth";

/** Upstream MCP servers whose tools the project's gateway clients may call. */
export function McpUpstreams({
  org,
  project,
  environment,
  admin,
  report,
}: {
  org: string;
  project: string;
  environment: string;
  admin: boolean;
  report: (failure: unknown) => void;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const params = { org, slug: project };
  const key = ["mcp-upstreams", org, project];
  const { data: upstreams = [] } = useQuery({
    queryKey: key,
    queryFn: async () =>
      (await api.GET("/v1/orgs/{org}/projects/{slug}/mcp-upstreams", { params: { path: params } })).data
        ?.upstreams ?? [],
  });
  const [auth, setAuth] = useState<Auth>("oauth");
  const [busy, setBusy] = useState(false);

  const add = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const optional = (name: string) => {
      const value = String(data.get(name) ?? "").trim();
      return value === "" ? undefined : value;
    };
    setBusy(true);
    const { error } = await api.PUT("/v1/orgs/{org}/projects/{slug}/mcp-upstreams/{name}", {
      params: { path: { ...params, name: String(data.get("name")) } },
      body: {
        url: String(data.get("url")),
        auth,
        secret_name: auth === "bearer" ? optional("secret_name") : undefined,
        client_id: auth === "oauth" ? optional("client_id") : undefined,
        scope: auth === "oauth" ? optional("scope") : undefined,
      },
    });
    setBusy(false);
    report(error);
    if (!error) form.reset();
    await queryClient.invalidateQueries({ queryKey: key });
  };
  const connect = async (name: string) => {
    const { data, error } = await api.POST("/v1/orgs/{org}/projects/{slug}/mcp-upstreams/{name}/connect", {
      params: { path: { ...params, name } },
      body: { environment },
    });
    report(error);
    if (data) window.open(data.authorize_url, "_blank", "noopener");
  };
  const remove = async (name: string) => {
    report(
      (await api.DELETE("/v1/orgs/{org}/projects/{slug}/mcp-upstreams/{name}", { params: { path: { ...params, name } } }))
        .error,
    );
    await queryClient.invalidateQueries({ queryKey: key });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("secrets.upstreams")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p className="text-muted-foreground">{t("secrets.upstreamsHelp")}</p>
        {upstreams.map((upstream) => {
          const connected = upstream.environments.includes(environment);
          return (
            <div key={upstream.name} className="flex flex-wrap items-center gap-2">
              <code>{upstream.name}</code>
              <span className="break-all">{upstream.url}</span>
              <Badge variant="outline">{t(`secrets.upstreamAuth.${upstream.auth}`)}</Badge>
              {upstream.auth !== "none" && (
                <Badge variant={connected ? "secondary" : "outline"}>
                  {connected ? t("secrets.connected", { environment }) : t("secrets.notConnected", { environment })}
                </Badge>
              )}
              {admin && upstream.auth === "oauth" && (
                <Button size="sm" variant="outline" onClick={() => void connect(upstream.name)}>
                  {connected ? t("secrets.reconnect") : t("secrets.connect")}
                </Button>
              )}
              {admin && (
                <Button size="sm" variant="ghost" onClick={() => void remove(upstream.name)}>
                  {t("secrets.delete")}
                </Button>
              )}
            </div>
          );
        })}
        {admin && (
          <form className="flex flex-wrap items-center gap-2" onSubmit={(event) => void add(event)}>
            <input className={input} name="name" required pattern="[a-z][a-z0-9-]*" maxLength={31} placeholder="github" aria-label={t("secrets.name")} />
            <input className={input} name="url" type="url" required placeholder="https://mcp.example.com/mcp" aria-label={t("secrets.upstreamUrl")} />
            <select className={input} value={auth} onChange={(event) => setAuth(event.target.value as Auth)} aria-label={t("secrets.upstreamAuthLabel")}>
              <option value="oauth">{t("secrets.upstreamAuth.oauth")}</option>
              <option value="bearer">{t("secrets.upstreamAuth.bearer")}</option>
              <option value="none">{t("secrets.upstreamAuth.none")}</option>
            </select>
            {auth === "bearer" && (
              <input className={`${input} font-mono`} name="secret_name" required placeholder="GITHUB_TOKEN" aria-label={t("secrets.secretName")} />
            )}
            {auth === "oauth" && (
              <>
                <input className={input} name="client_id" placeholder={t("secrets.clientIdOptional")} aria-label={t("secrets.clientIdOptional")} />
                <input className={input} name="scope" placeholder={t("secrets.scopeOptional")} aria-label={t("secrets.scopeOptional")} />
              </>
            )}
            <Button type="submit" size="sm" disabled={busy}>
              {t("secrets.set")}
            </Button>
          </form>
        )}
      </CardContent>
    </Card>
  );
}
