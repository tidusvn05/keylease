import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api/client";
import { orgQuery } from "@/lib/queries";

export const Route = createFileRoute("/secrets")({
  validateSearch: z.object({
    org: z.string().min(1),
    project: z.string().min(1),
    environment: z.string().optional(),
  }),
  component: Secrets,
});

const input = "border-input bg-background h-9 rounded-md border px-3 text-sm";

function Secrets() {
  const { t, i18n } = useTranslation();
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const queryClient = useQueryClient();
  const { data: org } = useQuery(orgQuery(search.org));
  const project = org?.projects.find((candidate) => candidate.slug === search.project);
  const environment = search.environment ?? project?.environments[0]?.slug ?? "";
  const params = { org: search.org, slug: search.project };
  const listKey = ["secrets", search.org, search.project, environment];
  const { data: secrets = [] } = useQuery({
    queryKey: listKey,
    enabled: environment !== "",
    queryFn: async () => {
      const { data } = await api.GET("/v1/orgs/{org}/projects/{slug}/secrets", {
        params: { path: params, query: { environment } },
      });
      return data?.secrets ?? [];
    },
  });
  const [shown, setShown] = useState<Record<string, string>>({});
  const [history, setHistory] = useState<{ name: string; versions: { version: number; deleted: boolean; created_at: string }[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const changesKey = ["changes", search.org, search.project];
  const { data: changes = [] } = useQuery({
    queryKey: changesKey,
    enabled: project?.my_role === "write" || project?.my_role === "admin",
    queryFn: async () => {
      const { data } = await api.GET("/v1/orgs/{org}/projects/{slug}/change-requests", { params: { path: params } });
      return data?.change_requests ?? [];
    },
  });
  const machinesKey = ["machines", search.org, search.project];
  const { data: machines = [] } = useQuery({
    queryKey: machinesKey,
    enabled: project?.my_role === "admin",
    queryFn: async () =>
      (await api.GET("/v1/orgs/{org}/projects/{slug}/machine-identities", { params: { path: params } })).data
        ?.identities ?? [],
  });
  const addMachine = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const field = (name: string) => String(data.get(name) ?? "");
    const { error } = await api.POST("/v1/orgs/{org}/projects/{slug}/machine-identities", {
      params: { path: params },
      body: {
        name: field("name"),
        environment,
        issuer: field("issuer"),
        audience: field("audience"),
        subject: field("subject"),
      },
    });
    report(error);
    if (!error) form.reset();
    await queryClient.invalidateQueries({ queryKey: machinesKey });
  };
  const [machineKey, setMachineKey] = useState<string | null>(null);
  const newKey = async (identity: string) => {
    const { data, error } = await api.POST("/v1/orgs/{org}/projects/{slug}/machine-identities/{identity}/keys", {
      params: { path: { ...params, identity } },
      body: { days: 90 },
    });
    report(error);
    setMachineKey(data?.key ?? null);
  };
  const revokeMachine = async (identity: string) => {
    report(
      (await api.DELETE("/v1/orgs/{org}/projects/{slug}/machine-identities/{identity}", {
        params: { path: { ...params, identity } },
      })).error,
    );
    await queryClient.invalidateQueries({ queryKey: machinesKey });
  };
  const writable = project?.my_role === "write" || project?.my_role === "admin";
  const path = (name: string) => ({ path: { ...params, environment, name } });
  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: listKey }),
      queryClient.invalidateQueries({ queryKey: changesKey }),
    ]);
  const decide = async (request: string, decision: "approve" | "reject") => {
    const { error } = await api.POST("/v1/orgs/{org}/projects/{slug}/change-requests/{request}/{decision}", {
      params: { path: { ...params, request, decision } },
    });
    report(error);
    await refresh();
  };
  const memberName = (account: string) =>
    org?.members.find((member) => member.account_id === account)?.display_name ?? account;
  const report = (failure: unknown) => setError(failure ? JSON.stringify(failure) : null);

  const reveal = async (name: string) => {
    if (name in shown) {
      setShown((current) => Object.fromEntries(Object.entries(current).filter(([key]) => key !== name)));
      return;
    }
    const { data, error } = await api.GET("/v1/orgs/{org}/projects/{slug}/secrets/{environment}/{name}", {
      params: path(name),
    });
    report(error);
    if (data) setShown((current) => ({ ...current, [name]: data.value }));
  };
  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const { data: written, error } = await api.PUT("/v1/orgs/{org}/projects/{slug}/secrets/{environment}/{name}", {
      params: path(String(data.get("name"))),
      body: { value: String(data.get("value")) },
    });
    report(error);
    setNotice(written?.status === "pending" ? t("secrets.pending") : null);
    if (!error) form.reset();
    await refresh();
  };
  const remove = async (name: string) => {
    const { error } = await api.DELETE("/v1/orgs/{org}/projects/{slug}/secrets/{environment}/{name}", {
      params: path(name),
    });
    report(error);
    await refresh();
  };
  const showHistory = async (name: string) => {
    const { data } = await api.GET("/v1/orgs/{org}/projects/{slug}/secrets/{environment}/{name}/versions", {
      params: path(name),
    });
    setHistory(data ? { name, versions: data.versions } : null);
  };
  const restore = async (name: string, version: number) => {
    const { error } = await api.POST("/v1/orgs/{org}/projects/{slug}/secrets/{environment}/{name}/restore", {
      params: path(name),
      body: { version },
    });
    report(error);
    setHistory(null);
    await refresh();
  };

  if (!project) return null;
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("secrets.title", { project: project.name })}</h1>
        <p className="text-muted-foreground">{t("secrets.description")}</p>
      </div>
      <div className="flex flex-wrap gap-2" role="tablist">
        {project.environments.map((candidate) => (
          <Button
            key={candidate.slug}
            role="tab"
            aria-selected={candidate.slug === environment}
            size="sm"
            variant={candidate.slug === environment ? "default" : "outline"}
            onClick={() => {
              setShown({});
              setHistory(null);
              void navigate({ search: (previous) => ({ ...previous, environment: candidate.slug }) });
            }}
          >
            {candidate.name}
            {candidate.protected && <Badge variant="destructive">!</Badge>}
          </Button>
        ))}
      </div>
      {error && (
        <p role="alert" className="text-destructive text-sm">
          {t("orgs.failed", { reason: error })}
        </p>
      )}
      {!writable && <p className="text-muted-foreground text-sm">{t("secrets.readOnly")}</p>}
      {notice && (
        <p role="status" className="text-sm">
          {notice}
        </p>
      )}
      {changes.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("secrets.changeRequests")}</CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2 text-sm">
              {changes.map((change) => (
                <li key={change.change_request_id} className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline">{change.environment}</Badge>
                  <span className="font-mono">{change.name}</span>
                  <span>{change.action}</span>
                  <span className="text-muted-foreground">
                    {t("secrets.requestedBy", { name: memberName(change.requested_by) })}
                  </span>
                  {project.my_role === "admin" && (
                    <>
                      <Button size="sm" onClick={() => void decide(change.change_request_id, "approve")}>
                        {t("secrets.approve")}
                      </Button>
                      <Button size="sm" variant="outline" onClick={() => void decide(change.change_request_id, "reject")}>
                        {t("secrets.reject")}
                      </Button>
                    </>
                  )}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t("secrets.name")}</TableHead>
            <TableHead>{t("secrets.value")}</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {secrets.length === 0 && (
            <TableRow>
              <TableCell colSpan={3} className="text-muted-foreground">
                {t("secrets.empty")}
              </TableCell>
            </TableRow>
          )}
          {secrets.map((secret) => (
            <TableRow key={secret.name}>
              <TableCell className="font-mono">{secret.name}</TableCell>
              <TableCell className="max-w-xs truncate font-mono">{shown[secret.name] ?? "••••••••"}</TableCell>
              <TableCell className="space-x-1 text-right whitespace-nowrap">
                <Button size="sm" variant="ghost" onClick={() => void reveal(secret.name)}>
                  {secret.name in shown ? t("secrets.hide") : t("secrets.reveal")}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => void showHistory(secret.name)}>
                  {t("secrets.history")}
                </Button>
                {writable && (
                  <Button size="sm" variant="ghost" onClick={() => void remove(secret.name)}>
                    {t("secrets.delete")}
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {writable && (
        <form className="flex flex-wrap items-center gap-2" onSubmit={(event) => void save(event)}>
          <input className={`${input} font-mono`} name="name" required pattern="[A-Za-z_][A-Za-z0-9_]*" placeholder="STRIPE_API_KEY" aria-label={t("secrets.name")} />
          <input className={input} name="value" type="password" required autoComplete="off" placeholder={t("secrets.value")} aria-label={t("secrets.value")} />
          <Button type="submit">{t("secrets.set")}</Button>
        </form>
      )}
      {project.my_role === "admin" && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("secrets.machines")}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p className="text-muted-foreground">{t("secrets.machinesHelp")}</p>
            {machines
              .filter((machine) => machine.environment === environment)
              .map((machine) => (
                <div key={machine.identity_id} className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{machine.name}</span>
                  <code className="text-xs">{machine.identity_id}</code>
                  <span className="text-muted-foreground">{machine.subject}</span>
                  <Button size="sm" variant="ghost" onClick={() => void newKey(machine.identity_id)}>
                    {t("secrets.newKey")}
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => void revokeMachine(machine.identity_id)}>
                    {t("secrets.revoke")}
                  </Button>
                </div>
              ))}
            {machineKey && (
              <p>
                {t("secrets.keyOnce")} <code className="bg-muted rounded px-1 font-mono break-all">{machineKey}</code>
              </p>
            )}
            <form className="flex flex-wrap items-center gap-2" onSubmit={(event) => void addMachine(event)}>
              <input className={input} name="name" required placeholder={t("secrets.name")} aria-label={t("secrets.name")} />
              <input className={input} name="issuer" required defaultValue="https://token.actions.githubusercontent.com" aria-label={t("secrets.issuer")} />
              <input className={input} name="audience" required defaultValue="keylease" aria-label={t("secrets.audience")} />
              <input className={input} name="subject" required placeholder="repo:acme/shop:ref:refs/heads/main" aria-label={t("secrets.subject")} />
              <Button type="submit" size="sm">
                {t("secrets.addMachine")}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}
      {history && (
        <Card>
          <CardHeader>
            <CardTitle className="font-mono text-base">
              {history.name} · {t("secrets.history")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ul className="space-y-1 text-sm">
              {history.versions.map((version) => (
                <li key={version.version} className="flex items-center gap-2">
                  <span>v{version.version}</span>
                  <span className="text-muted-foreground">
                    {new Date(version.created_at).toLocaleString(i18n.language)}
                  </span>
                  {version.deleted ? (
                    <Badge variant="outline">{t("secrets.deleted")}</Badge>
                  ) : (
                    writable && (
                      <Button size="sm" variant="ghost" onClick={() => void restore(history.name, version.version)}>
                        {t("secrets.restore")}
                      </Button>
                    )
                  )}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
