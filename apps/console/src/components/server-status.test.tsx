import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ServerStatus } from "@/components/server-status";
import i18n from "@/i18n";

function renderStatus() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ServerStatus />
    </QueryClientProvider>,
  );
}

describe("ServerStatus", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("shows the contract version when the server answers", async () => {
    await i18n.changeLanguage("en");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ ok: true, service: "keylease-server", contract_version: "1" }),
      ),
    );
    renderStatus();
    expect(await screen.findByText("Server online")).toBeInTheDocument();
    expect(screen.getByText("Contract 1")).toBeInTheDocument();
  });

  it("reports an unreachable server", async () => {
    await i18n.changeLanguage("vi");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError("network down");
      }),
    );
    renderStatus();
    expect(await screen.findByText("Không kết nối được server")).toBeInTheDocument();
  });
});
