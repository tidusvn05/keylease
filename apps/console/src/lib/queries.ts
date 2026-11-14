import { queryOptions } from "@tanstack/react-query";
import { api } from "@/lib/api/client";

export const healthQuery = queryOptions({
  queryKey: ["health"],
  queryFn: async () => {
    const { data, error } = await api.GET("/healthz");
    if (error !== undefined || data === undefined) throw new Error("server unreachable");
    return data;
  },
  refetchInterval: 30_000,
  retry: false,
});
