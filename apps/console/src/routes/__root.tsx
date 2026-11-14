import { type QueryClient, useQuery } from "@tanstack/react-query";
import { createRootRouteWithContext, Outlet } from "@tanstack/react-router";
import { lazy, Suspense } from "react";
import { useTranslation } from "react-i18next";
import { AppShell } from "@/components/app-shell";
import { SignIn } from "@/components/sign-in";
import { meQuery, NotSignedIn } from "@/lib/queries";

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
  const me = useQuery(meQuery);
  if (me.isPending) return null;
  if (me.error instanceof NotSignedIn) return <SignIn />;
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
