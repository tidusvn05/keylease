import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { components } from "@/lib/api/schema";
import { decideApproval, type TrustDecision } from "@/lib/approvals";
import { disablePush, enablePush, pushEnabled, pushSupported } from "@/lib/push";
import { approvalsQuery } from "@/lib/queries";

export const Route = createFileRoute("/approvals")({
  component: Approvals,
});

type Node = components["schemas"]["NodeApprovals"];
type Pending = components["schemas"]["PendingApproval"];
type Decision = components["schemas"]["ConsoleDecision"];

const durations = ["once", "30m", "1h", "6h", "1d"] as const;
const scopes = ["resource", "item", "project"] as const;
/** A node that has not reported for this long is probably not running. */
const STALE_MS = 60_000;

function Approvals() {
  const { t, i18n } = useTranslation();
  const { data, dataUpdatedAt } = useQuery(approvalsQuery);
  const nodes = data?.nodes ?? [];
  const decisions = data?.decisions ?? [];
  const time = (value: string) => new Date(value).toLocaleString(i18n.language);
  const nodeName = (member: string) => nodes.find((n) => n.member_id === member)?.name ?? member;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{t("approvals.title")}</h1>
          <p className="text-muted-foreground">{t("approvals.description")}</p>
        </div>
        <NotifyToggle />
      </div>
      {data !== undefined && nodes.length === 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t("approvals.noNodes")}</CardTitle>
            <CardDescription>{t("approvals.enableHelp")}</CardDescription>
          </CardHeader>
          <CardContent>
            <code className="bg-muted rounded px-2 py-1 text-sm">keylease cloud console-approvals enable</code>
          </CardContent>
        </Card>
      )}
      {nodes.map((node) => (
        <NodeCard key={node.member_id} node={node} decisions={decisions} time={time} now={dataUpdatedAt} />
      ))}
      {decisions.length > 0 && (
        <div className="space-y-2">
          <h2 className="text-lg font-semibold">{t("approvals.recent")}</h2>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("approvals.when")}</TableHead>
                <TableHead>{t("approvals.node")}</TableHead>
                <TableHead>{t("approvals.decision")}</TableHead>
                <TableHead>{t("approvals.result")}</TableHead>
                <TableHead>{t("approvals.passkey")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {decisions.map((decision) => (
                <TableRow key={decision.decision_id}>
                  <TableCell>{time(decision.created_at)}</TableCell>
                  <TableCell>{nodeName(decision.member_id)}</TableCell>
                  <TableCell>{decision.approve ? t("approvals.approve") : t("approvals.deny")}</TableCell>
                  <TableCell>
                    <Outcome decision={decision} />
                  </TableCell>
                  <TableCell>{decision.passkey_name}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}

/** Web Push for this browser: a notification when a node reports a new request. */
function NotifyToggle() {
  const { t } = useTranslation();
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (pushSupported()) void pushEnabled().then(setEnabled, () => setEnabled(false));
  }, []);
  if (!pushSupported()) return null;
  const toggle = async () => {
    setBusy(true);
    setFailed(false);
    try {
      if (enabled) {
        await disablePush();
        setEnabled(false);
      } else {
        const ok = await enablePush(navigator.userAgent.slice(0, 80));
        setEnabled(ok);
        setFailed(!ok);
      }
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="text-right">
      <Button size="sm" variant="outline" disabled={busy || enabled === null} onClick={() => void toggle()}>
        {enabled ? t("approvals.notifyOff") : t("approvals.notifyOn")}
      </Button>
      {failed && <p className="text-destructive mt-1 text-xs">{t("approvals.notifyFailed")}</p>}
    </div>
  );
}

function Outcome({ decision }: { decision: Decision }) {
  const { t } = useTranslation();
  if (decision.outcome === "approved") return <Badge variant="secondary">{t("approvals.outcomes.approved")}</Badge>;
  if (decision.outcome === "denied") return <Badge variant="outline">{t("approvals.outcomes.denied")}</Badge>;
  if (decision.outcome === "rejected") {
    return (
      <span className="text-destructive text-sm">
        {t("approvals.outcomes.rejected")}
        {decision.reason ? `: ${decision.reason}` : ""}
      </span>
    );
  }
  return <span className="text-muted-foreground text-sm">{t("approvals.outcomes.waiting")}</span>;
}

function NodeCard({
  node,
  decisions,
  time,
  now,
}: {
  node: Node;
  decisions: Decision[];
  time: (value: string) => string;
  /** When the list was fetched. */
  now: number;
}) {
  const { t } = useTranslation();
  const stale = now - new Date(node.reported_at).getTime() > STALE_MS;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          {node.name}
          {stale && <Badge variant="outline">{t("approvals.stale")}</Badge>}
        </CardTitle>
        <CardDescription>{t("approvals.reported", { time: time(node.reported_at) })}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {node.approvals.length === 0 && <p className="text-muted-foreground text-sm">{t("approvals.none")}</p>}
        {node.approvals.map((approval) => (
          <ApprovalRow
            key={approval.id}
            member={node.member_id}
            approval={approval}
            sent={decisions.some((d) => d.approval_id === approval.id && d.outcome == null)}
            time={time}
          />
        ))}
      </CardContent>
    </Card>
  );
}

function ApprovalRow({
  member,
  approval,
  sent,
  time,
}: {
  member: string;
  approval: Pending;
  sent: boolean;
  time: (value: string) => string;
}) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [duration, setDuration] = useState<TrustDecision["duration"]>("once");
  const [scope, setScope] = useState<TrustDecision["scope"]>("item");
  const [failure, setFailure] = useState<string | null>(null);
  const decide = useMutation({
    mutationFn: (approve: boolean) =>
      decideApproval(member, approval.id, approve, approve && duration !== "once" ? { duration, scope } : undefined),
    onMutate: () => setFailure(null),
    onError: (error) =>
      setFailure(
        error instanceof Error && error.message === "invalid_request"
          ? t("approvals.errors.gone")
          : error instanceof Error && error.message === "denied"
            ? t("approvals.errors.passkey")
            : t("approvals.errors.cancelled"),
      ),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["approvals"] }),
  });
  const summary = approval.semantic_summary;
  return (
    <div className="space-y-2 rounded-md border p-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div className="font-medium">
          <span className="font-mono">{summary?.operation ?? approval.action ?? "—"}</span>
          {approval.risk && (
            <Badge variant="outline" className="ml-2">
              {approval.risk}
            </Badge>
          )}
        </div>
        <span className="text-muted-foreground text-xs">
          {t("approvals.expires", { time: time(approval.expires_at) })}
        </span>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
        <dt className="text-muted-foreground">{t("approvals.agent")}</dt>
        <dd className="font-mono break-all">{approval.agent_id ?? "—"}</dd>
        <dt className="text-muted-foreground">{t("approvals.resource")}</dt>
        <dd className="font-mono break-all">{summary?.target ?? approval.resource ?? "—"}</dd>
        {approval.purpose && (
          <>
            <dt className="text-muted-foreground">{t("approvals.purpose")}</dt>
            <dd>
              <span className="italic">“{approval.purpose}”</span>{" "}
              <span className="text-muted-foreground text-xs">{t("approvals.purposeHint")}</span>
            </dd>
          </>
        )}
        <dt className="text-muted-foreground">{t("approvals.digest")}</dt>
        <dd className="font-mono text-xs">{approval.request_digest_hex.slice(0, 16)}…</dd>
      </dl>
      {sent ? (
        <p className="text-muted-foreground text-sm">{t("approvals.sent")}</p>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <label className="text-sm">
            {t("approvals.trustFor")}{" "}
            <select
              className="bg-background rounded-md border px-2 py-1"
              value={duration}
              onChange={(event) => setDuration(event.target.value as TrustDecision["duration"])}
            >
              {durations.map((value) => (
                <option key={value} value={value}>
                  {t(`approvals.durations.${value}`)}
                </option>
              ))}
            </select>
          </label>
          {duration !== "once" && (
            <label className="text-sm">
              {t("approvals.scope")}{" "}
              <select
                className="bg-background rounded-md border px-2 py-1"
                value={scope}
                onChange={(event) => setScope(event.target.value as TrustDecision["scope"])}
              >
                {scopes.map((value) => (
                  <option key={value} value={value}>
                    {t(`approvals.scopes.${value}`)}
                  </option>
                ))}
              </select>
            </label>
          )}
          <Button size="sm" disabled={decide.isPending} onClick={() => decide.mutate(true)}>
            {t("approvals.approve")}
          </Button>
          <Button size="sm" variant="outline" disabled={decide.isPending} onClick={() => decide.mutate(false)}>
            {t("approvals.deny")}
          </Button>
        </div>
      )}
      {failure && <p className="text-destructive text-sm">{failure}</p>}
    </div>
  );
}
