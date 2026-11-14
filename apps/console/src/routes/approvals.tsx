import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { ComingSoon } from "@/components/coming-soon";

export const Route = createFileRoute("/approvals")({
  component: Page,
});

function Page() {
  const { t } = useTranslation();
  return <ComingSoon title={t("approvals.title")} description={t("approvals.description")} />;
}
