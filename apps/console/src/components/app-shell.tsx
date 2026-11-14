import { Link } from "@tanstack/react-router";
import { History, LayoutDashboard, MonitorSmartphone, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { ServerStatus } from "@/components/server-status";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { languages, setLanguage } from "@/i18n";

const nav = [
  { to: "/", key: "nav.overview", icon: LayoutDashboard },
  { to: "/devices", key: "nav.devices", icon: MonitorSmartphone },
  { to: "/approvals", key: "nav.approvals", icon: ShieldCheck },
  { to: "/audit", key: "nav.audit", icon: History },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const { t, i18n } = useTranslation();
  return (
    <div className="flex min-h-svh flex-col md:flex-row">
      <aside className="border-b md:w-60 md:shrink-0 md:border-r md:border-b-0">
        <div className="px-4 py-4 font-semibold">{t("app.name")}</div>
        <nav className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-col md:pb-0">
          {nav.map(({ to, key, icon: Icon }) => (
            <Link
              key={to}
              to={to}
              activeOptions={{ exact: to === "/" }}
              className="text-muted-foreground hover:bg-accent hover:text-accent-foreground flex items-center gap-2 rounded-md px-3 py-2 text-sm whitespace-nowrap"
              activeProps={{ className: "bg-accent text-accent-foreground font-medium" }}
            >
              <Icon className="size-4" aria-hidden />
              {t(key)}
            </Link>
          ))}
        </nav>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-4 px-4 py-3 md:px-6">
          <ServerStatus />
          <div className="flex items-center gap-1" role="group" aria-label={t("language")}>
            {languages.map((lang) => (
              <Button
                key={lang}
                size="sm"
                variant={i18n.language === lang ? "secondary" : "ghost"}
                aria-pressed={i18n.language === lang}
                onClick={() => setLanguage(lang)}
              >
                {lang.toUpperCase()}
              </Button>
            ))}
          </div>
        </header>
        <Separator />
        <main className="flex-1 px-4 py-6 md:px-6">{children}</main>
      </div>
    </div>
  );
}
