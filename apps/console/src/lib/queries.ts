import { queryOptions } from "@tanstack/react-query";
import { api } from "@/lib/api/client";

export class NotSignedIn extends Error {}

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

export const meQuery = queryOptions({
  queryKey: ["me"],
  queryFn: async () => {
    const { data, response } = await api.GET("/v1/console/me");
    if (response.status === 403) throw new NotSignedIn();
    if (data === undefined) throw new Error("server unreachable");
    return data;
  },
  retry: false,
});

export const devicesQuery = queryOptions({
  queryKey: ["devices"],
  queryFn: async () => {
    const { data } = await api.GET("/v1/console/devices");
    if (data === undefined) throw new Error("could not load devices");
    return data.devices;
  },
});

export const passkeysQuery = queryOptions({
  queryKey: ["passkeys"],
  queryFn: async () => {
    const { data } = await api.GET("/v1/console/passkeys");
    if (data === undefined) throw new Error("could not load passkeys");
    return data.passkeys;
  },
});

export const orgsQuery = queryOptions({
  queryKey: ["orgs"],
  queryFn: async () => {
    const { data } = await api.GET("/v1/orgs");
    if (data === undefined) throw new Error("could not load organizations");
    return data.orgs;
  },
});

export const orgQuery = (id: string) =>
  queryOptions({
    queryKey: ["org", id],
    queryFn: async () => {
      const { data } = await api.GET("/v1/orgs/{org}", { params: { path: { org: id } } });
      if (data === undefined) throw new Error("could not load the organization");
      return data;
    },
  });

export const ssoQuery = queryOptions({
  queryKey: ["sso"],
  queryFn: async () => {
    const { data } = await api.GET("/v1/console/sso");
    return data ?? { enabled: false };
  },
  retry: false,
});
