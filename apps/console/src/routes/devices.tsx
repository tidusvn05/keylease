import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
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

export const Route = createFileRoute("/devices")({
  component: Devices,
});

function Devices() {
  const { t, i18n } = useTranslation();
  const queryClient = useQueryClient();
  const { data: devices = [] } = useQuery(devicesQuery);
  const revoke = useMutation({
    mutationFn: async (member: string) => {
      await api.DELETE("/v1/console/devices/{member}", { params: { path: { member } } });
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["devices"] }),
  });
  const date = (value: string) => new Date(value).toLocaleDateString(i18n.language);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{t("devices.title")}</h1>
        <p className="text-muted-foreground">{t("devices.description")}</p>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t("devices.name")}</TableHead>
            <TableHead>{t("devices.role")}</TableHead>
            <TableHead>{t("devices.added")}</TableHead>
            <TableHead>{t("devices.status")}</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {devices.map((device) => (
            <TableRow key={device.member_id}>
              <TableCell className="font-medium">{device.name}</TableCell>
              <TableCell>{t(`devices.roles.${device.role}`)}</TableCell>
              <TableCell>{date(device.created_at)}</TableCell>
              <TableCell>
                {device.revoked_at ? (
                  <Badge variant="outline">{t("devices.revoked")}</Badge>
                ) : (
                  <Badge variant="secondary">{t("devices.active")}</Badge>
                )}
              </TableCell>
              <TableCell className="text-right">
                {device.role !== "owner" && !device.revoked_at && (
                  <Button
                    size="sm"
                    variant="destructive"
                    disabled={revoke.isPending}
                    onClick={() => {
                      if (window.confirm(t("devices.confirmRevoke", { name: device.name }))) {
                        revoke.mutate(device.member_id);
                      }
                    }}
                  >
                    {t("devices.revoke")}
                  </Button>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
