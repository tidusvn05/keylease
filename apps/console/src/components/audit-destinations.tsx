import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api/client";

const input = "border-input bg-background h-9 rounded-md border px-3 text-sm";
type Format = "jsonl" | "syslog" | "splunk_hec";

/** SIEM collectors the organization's audit is pushed to (owners and admins). */
export function AuditDestinations({ org }: { org: string }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const key = ["audit-destinations", org];
  const { data: destinations = [] } = useQuery({
    queryKey: key,
    queryFn: async () =>
      (await api.GET("/v1/orgs/{org}/audit/destinations", { params: { path: { org } } })).data?.destinations ?? [],
    refetchInterval: 15_000,
  });
  const [message, setMessage] = useState<string | null>(null);

  const add = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const secret = String(data.get("secret") ?? "");
    const { error } = await api.PUT("/v1/orgs/{org}/audit/destinations/{name}", {
      params: { path: { org, name: String(data.get("name")) } },
      body: {
        url: String(data.get("url")),
        format: String(data.get("format")) as Format,
        secret: secret === "" ? undefined : secret,
        start: data.get("beginning") === "on" ? "beginning" : "now",
      },
    });
    setMessage(error ? t("audit.destinationFailed") : null);
    if (!error) form.reset();
    await queryClient.invalidateQueries({ queryKey: key });
  };
  const test = async (name: string) => {
    const { data } = await api.POST("/v1/orgs/{org}/audit/destinations/{name}/test", {
      params: { path: { org, name } },
    });
    setMessage(data?.ok ? t("audit.testOk", { name }) : t("audit.testFailed", { name, error: data?.error ?? "" }));
  };
  const remove = async (name: string) => {
    await api.DELETE("/v1/orgs/{org}/audit/destinations/{name}", { params: { path: { org, name } } });
    await queryClient.invalidateQueries({ queryKey: key });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">{t("audit.destinations")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">{t("audit.destinationsHelp")}</p>
        {destinations.map((destination) => (
          <div key={destination.name} className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <code>{destination.name}</code>
              <span className="break-all">{destination.url}</span>
              <Badge variant="outline">{t(`audit.formats.${destination.format}`)}</Badge>
              {destination.failures > 0 ? (
                <Badge variant="outline">{t("audit.failing", { count: destination.failures })}</Badge>
              ) : (
                <Badge variant="secondary">{t("audit.behind", { count: destination.behind })}</Badge>
              )}
              <Button size="sm" variant="outline" onClick={() => void test(destination.name)}>
                {t("audit.test")}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => void remove(destination.name)}>
                {t("orgs.remove")}
              </Button>
            </div>
            {destination.last_error && <p className="text-destructive text-xs">{destination.last_error}</p>}
          </div>
        ))}
        {message && <p role="status">{message}</p>}
        <form className="flex flex-wrap items-center gap-2" onSubmit={(event) => void add(event)}>
          <input className={input} name="name" required pattern="[a-z][a-z0-9-]*" placeholder="splunk" aria-label={t("audit.destinationName")} />
          <input className={input} name="url" type="url" required placeholder="https://siem.example.com/services/collector" aria-label={t("audit.destinationUrl")} />
          <select className={input} name="format" defaultValue="jsonl" aria-label={t("audit.format")}>
            <option value="jsonl">{t("audit.formats.jsonl")}</option>
            <option value="syslog">{t("audit.formats.syslog")}</option>
            <option value="splunk_hec">{t("audit.formats.splunk_hec")}</option>
          </select>
          <input className={input} name="secret" type="password" autoComplete="off" placeholder={t("audit.token")} aria-label={t("audit.token")} />
          <label className="flex items-center gap-1">
            <input type="checkbox" name="beginning" />
            {t("audit.fromBeginning")}
          </label>
          <Button type="submit" size="sm">
            {t("secrets.set")}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
