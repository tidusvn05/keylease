import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import { healthQuery } from "@/lib/queries";
import { cn } from "@/lib/utils";

export function ServerStatus() {
  const { t } = useTranslation();
  const { data, isPending, isError } = useQuery(healthQuery);

  const label = isPending ? t("server.checking") : isError ? t("server.offline") : t("server.online");
  return (
    <div className="flex items-center gap-2 text-sm" role="status">
      <span
        aria-hidden
        className={cn(
          "size-2 rounded-full",
          isPending && "bg-muted-foreground",
          isError && "bg-destructive",
          data !== undefined && "bg-success",
        )}
      />
      <span>{label}</span>
      {data !== undefined && (
        <Badge variant="outline">{t("server.contract", { version: data.contract_version })}</Badge>
      )}
    </div>
  );
}
