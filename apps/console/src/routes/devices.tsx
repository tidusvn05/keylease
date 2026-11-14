import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { ComingSoon } from "@/components/coming-soon";

export const Route = createFileRoute("/devices")({
  component: Page,
});

function Page() {
  const { t } = useTranslation();
  return <ComingSoon title={t("devices.title")} description={t("devices.description")} />;
}
