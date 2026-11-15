import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { api } from "@/lib/api/client";
import { devicesQuery } from "@/lib/queries";

export const Route = createFileRoute("/audit")({
  component: Audit,
});

const PAGE = 100;

function Audit() {
  const { t, i18n } = useTranslation();
  const [member, setMember] = useState("");
  const { data: devices = [] } = useQuery(devicesQuery);
  const audit = useInfiniteQuery({
    queryKey: ["audit", member],
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => {
      const { data } = await api.GET("/v1/console/audit", {
        params: { query: { member: member || undefined, before: pageParam, limit: PAGE } },
      });
      if (data === undefined) throw new Error("could not load the audit log");
      return data;
    },
    getNextPageParam: (page) => page.next ?? undefined,
  });
  const events = audit.data?.pages.flatMap((page) => page.events) ?? [];
  const time = (value: string) => new Date(value).toLocaleString(i18n.language);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("audit.title")}</h1>
        <p className="text-muted-foreground">{t("audit.description")}</p>
      </div>
      <label className="text-sm">
        {t("audit.node")}{" "}
        <select
          className="bg-background rounded-md border px-2 py-1"
          value={member}
          onChange={(event) => setMember(event.target.value)}
        >
          <option value="">{t("audit.allNodes")}</option>
          {devices
            .filter((device) => !device.revoked_at)
            .map((device) => (
              <option key={device.member_id} value={device.member_id}>
                {device.name}
              </option>
            ))}
        </select>
      </label>
      {audit.isSuccess && events.length === 0 && (
        <p className="text-muted-foreground text-sm">{t("audit.empty")}</p>
      )}
      {events.length > 0 && (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("audit.when")}</TableHead>
              <TableHead>{t("audit.node")}</TableHead>
              <TableHead>{t("audit.who")}</TableHead>
              <TableHead>{t("audit.action")}</TableHead>
              <TableHead>{t("audit.resource")}</TableHead>
              <TableHead>{t("audit.result")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {events.map(({ member_id, node, seq, event }) => (
              <TableRow key={`${member_id}-${seq}`}>
                <TableCell className="whitespace-nowrap">{time(event.timestamp)}</TableCell>
                <TableCell>{node}</TableCell>
                <TableCell className="font-mono text-xs break-all">{event.agent_id}</TableCell>
                <TableCell className="font-mono text-xs">{event.action}</TableCell>
                <TableCell className="font-mono text-xs break-all">{event.resource}</TableCell>
                <TableCell>
                  <Badge variant={event.decision === "deny" ? "outline" : "secondary"}>{event.outcome}</Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {audit.hasNextPage && (
        <Button variant="outline" disabled={audit.isFetchingNextPage} onClick={() => void audit.fetchNextPage()}>
          {t("audit.more")}
        </Button>
      )}
    </div>
  );
}
