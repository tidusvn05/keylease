import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api/client";
import { orgsQuery } from "@/lib/queries";

export const Route = createFileRoute("/orgs")({
  component: Orgs,
});

const input =
  "border-input bg-background h-9 w-full rounded-md border px-3 text-sm focus-visible:outline-2";

function Orgs() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const { data: orgs = [] } = useQuery(orgsQuery);
  const [error, setError] = useState<string | null>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["orgs"] });

  const create = useMutation({
    mutationFn: async (body: { name: string; display_name: string }) => {
      const { error } = await api.POST("/v1/orgs", { body });
      if (error) throw new Error(JSON.stringify(error));
    },
    onSuccess: () => setError(null),
    onError: (failure) => setError(failure.message),
    onSettled: refresh,
  });
  const join = useMutation({
    mutationFn: async (body: { code: string; display_name: string }) => {
      const { error } = await api.POST("/v1/orgs/join", { body });
      if (error) throw new Error(JSON.stringify(error));
    },
    onSuccess: () => setError(null),
    onError: (failure) => setError(failure.message),
    onSettled: refresh,
  });

  const submit = (event: FormEvent<HTMLFormElement>, action: (data: FormData) => void) => {
    event.preventDefault();
    action(new FormData(event.currentTarget));
    event.currentTarget.reset();
  };
  const text = (data: FormData, name: string) => String(data.get(name) ?? "");

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("orgs.title")}</h1>
        <p className="text-muted-foreground">{t("orgs.description")}</p>
      </div>
      {error && (
        <p role="alert" className="text-destructive text-sm">
          {t("orgs.failed", { reason: error })}
        </p>
      )}
      <div className="grid gap-4 md:grid-cols-2">
        {orgs.length === 0 && <p className="text-muted-foreground text-sm">{t("orgs.none")}</p>}
        {orgs.map((org) => (
          <Card key={org.org_id}>
            <CardHeader>
              <CardTitle>
                <Link to="/org" search={{ id: org.org_id }} className="underline">
                  {org.name}
                </Link>
              </CardTitle>
              <CardDescription>
                {t("orgs.myRole", { role: t(`orgs.roles.${org.role as "owner"}`) })}
              </CardDescription>
            </CardHeader>
          </Card>
        ))}
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("orgs.create")}</CardTitle>
          </CardHeader>
          <CardContent>
            <form
              className="space-y-2"
              onSubmit={(event) =>
                submit(event, (data) =>
                  create.mutate({ name: text(data, "name"), display_name: text(data, "display_name") }),
                )
              }
            >
              <input className={input} name="name" required placeholder={t("orgs.name")} aria-label={t("orgs.name")} />
              <input className={input} name="display_name" required placeholder={t("orgs.yourName")} aria-label={t("orgs.yourName")} />
              <Button type="submit" disabled={create.isPending}>
                {t("orgs.create")}
              </Button>
            </form>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("orgs.join")}</CardTitle>
          </CardHeader>
          <CardContent>
            <form
              className="space-y-2"
              onSubmit={(event) =>
                submit(event, (data) =>
                  join.mutate({ code: text(data, "code"), display_name: text(data, "display_name") }),
                )
              }
            >
              <input className={input} name="code" required placeholder={t("orgs.code")} aria-label={t("orgs.code")} autoComplete="off" />
              <input className={input} name="display_name" required placeholder={t("orgs.yourName")} aria-label={t("orgs.yourName")} />
              <Button type="submit" variant="secondary" disabled={join.isPending}>
                {t("orgs.join")}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
