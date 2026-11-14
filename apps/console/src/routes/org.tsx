import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { GatewayClients } from "@/components/gateway-clients";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api/client";
import { meQuery, orgQuery } from "@/lib/queries";

export const Route = createFileRoute("/org")({
  validateSearch: z.object({ id: z.string().min(1) }),
  component: OrgPage,
});

const input = "border-input bg-background h-9 rounded-md border px-3 text-sm";

function OrgPage() {
  const { t } = useTranslation();
  const { id } = Route.useSearch();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { data: me } = useQuery(meQuery);
  const { data: org } = useQuery(orgQuery(id));
  const [code, setCode] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["org", id] });
  const run = (action: () => Promise<{ error?: unknown }>) =>
    action().then(({ error }) => {
      setError(error ? JSON.stringify(error) : null);
      return refresh();
    });

  const leave = useMutation({
    mutationFn: () =>
      api.DELETE("/v1/orgs/{org}/members/{account}", {
        params: { path: { org: id, account: me?.account_id ?? "" } },
      }),
    onSuccess: async ({ error }) => {
      if (error) {
        setError(JSON.stringify(error));
        return;
      }
      await queryClient.invalidateQueries({ queryKey: ["orgs"] });
      await navigate({ to: "/orgs" });
    },
  });

  if (!org) return null;
  const manager = org.my_role === "owner" || org.my_role === "admin";
  const path = { org: id };

  const invite = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const role = String(new FormData(event.currentTarget).get("role"));
    void api.POST("/v1/orgs/{org}/invites", { params: { path }, body: { role } }).then(({ data, error }) => {
      setCode(data?.code ?? null);
      setError(error ? JSON.stringify(error) : null);
    });
  };
  const newProject = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    event.currentTarget.reset();
    void run(() =>
      api.POST("/v1/orgs/{org}/projects", {
        params: { path },
        body: { slug: String(data.get("slug")), name: String(data.get("name")) },
      }),
    );
  };
  const grant = (slug: string, event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    void run(() =>
      api.PUT("/v1/orgs/{org}/projects/{slug}/access/{account}", {
        params: { path: { org: id, slug, account: String(data.get("account")) } },
        body: { role: String(data.get("role")) },
      }),
    );
  };
  const name = (account: string) =>
    org.members.find((member) => member.account_id === account)?.display_name ?? account;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{org.name}</h1>
          <p className="text-muted-foreground">
            {t("orgs.myRole", { role: t(`orgs.roles.${org.my_role as "owner"}`) })}
          </p>
        </div>
        <Button variant="outline" onClick={() => leave.mutate()}>
          {t("orgs.leave")}
        </Button>
      </div>
      {error && (
        <p role="alert" className="text-destructive text-sm">
          {t("orgs.failed", { reason: error })}
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("orgs.members")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("devices.name")}</TableHead>
                <TableHead>{t("devices.role")}</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {org.members.map((member) => (
                <TableRow key={member.account_id}>
                  <TableCell>{member.display_name}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">{t(`orgs.roles.${member.role as "owner"}`)}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    {manager && member.account_id !== me?.account_id && (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          void run(() =>
                            api.DELETE("/v1/orgs/{org}/members/{account}", {
                              params: { path: { org: id, account: member.account_id } },
                            }),
                          )
                        }
                      >
                        {t("orgs.remove")}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {manager && (
            <form className="flex flex-wrap items-center gap-2" onSubmit={invite}>
              <select className={input} name="role" defaultValue="member" aria-label={t("devices.role")}>
                <option value="member">{t("orgs.roles.member")}</option>
                <option value="viewer">{t("orgs.roles.viewer")}</option>
                <option value="admin">{t("orgs.roles.admin")}</option>
              </select>
              <Button type="submit">{t("orgs.invite")}</Button>
            </form>
          )}
          {code && (
            <p className="text-sm">
              {t("orgs.inviteCode")} <code className="bg-muted rounded px-1 font-mono">{code}</code>
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t("orgs.projects")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {org.projects.map((project) => (
            <div key={project.slug} className="space-y-2 rounded-md border p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{project.name}</span>
                <code className="text-muted-foreground text-xs">{project.slug}</code>
                <Badge variant="outline">{t(`orgs.projectRoles.${project.my_role as "read"}`)}</Badge>
                <Link to="/secrets" search={{ org: id, project: project.slug }} className="text-sm underline">
                  {t("secrets.open")}
                </Link>
                {project.environments.map((environment) => (
                  <Badge key={environment.slug} variant={environment.protected ? "destructive" : "secondary"}>
                    {environment.name}
                  </Badge>
                ))}
              </div>
              {manager && (
                <>
                  <ul className="text-sm">
                    {project.access.map((grant) => (
                      <li key={grant.account_id}>
                        {name(grant.account_id)}: {t(`orgs.projectRoles.${grant.role as "read"}`)}
                      </li>
                    ))}
                  </ul>
                  <form className="flex flex-wrap items-center gap-2" onSubmit={(event) => grant(project.slug, event)}>
                    <select className={input} name="account" aria-label={t("orgs.members")}>
                      {org.members.map((member) => (
                        <option key={member.account_id} value={member.account_id}>
                          {member.display_name}
                        </option>
                      ))}
                    </select>
                    <select className={input} name="role" defaultValue="read" aria-label={t("orgs.access")}>
                      <option value="read">{t("orgs.projectRoles.read")}</option>
                      <option value="write">{t("orgs.projectRoles.write")}</option>
                      <option value="admin">{t("orgs.projectRoles.admin")}</option>
                    </select>
                    <Button type="submit" size="sm" variant="secondary">
                      {t("orgs.grant")}
                    </Button>
                  </form>
                </>
              )}
            </div>
          ))}
          {manager && (
            <form className="flex flex-wrap items-center gap-2" onSubmit={newProject}>
              <input className={input} name="slug" required placeholder={t("orgs.slug")} aria-label={t("orgs.slug")} />
              <input className={input} name="name" required placeholder={t("orgs.name")} aria-label={t("orgs.name")} />
              <Button type="submit">{t("orgs.newProject")}</Button>
            </form>
          )}
        </CardContent>
      </Card>
      {manager && (
        <GatewayClients
          org={id}
          environments={org.projects.flatMap((project) =>
            project.environments.map((environment) => ({ project: project.slug, environment: environment.slug })),
          )}
        />
      )}
    </div>
  );
}
