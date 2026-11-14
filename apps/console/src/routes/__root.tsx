import type { QueryClient } from "@tanstack/react-query";
import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import { lazy, Suspense } from "react";
import { useTranslation } from "react-i18next";
import { AppShell } from "@/components/app-shell";

// Devtools are loaded only in development builds.
const RouterDevtools = import.meta.env.DEV
  ? lazy(() =>
      import("@tanstack/react-router-devtools").then((m) => ({ default: m.TanStackRouterDevtools })),
    )
  : () => null;

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: RootLayout,
  notFoundComponent: NotFound,
});

function RootLayout() {
  return (
    <AppShell>
      <Outlet />
      <Suspense>
        <RouterDevtools />
      </Suspense>
    </AppShell>
  );
}

function NotFound() {
  const { t } = useTranslation();
  return <p className="text-muted-foreground">{t("notFound")}</p>;
}
