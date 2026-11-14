import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { ComingSoon } from "@/components/coming-soon";

export const Route = createFileRoute("/audit")({
  component: Page,
});

function Page() {
  const { t } = useTranslation();
  return <ComingSoon title={t("audit.title")} description={t("audit.description")} />;
}
