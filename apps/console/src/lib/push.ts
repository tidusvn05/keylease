import { api } from "@/lib/api/client";
import { consoleBase } from "@/lib/paths";

/** Whether this browser can receive Web Push notifications. */
export function pushSupported(): boolean {
  return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
}

function serverKey(text: string): Uint8Array<ArrayBuffer> {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  const bytes = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

async function registration(): Promise<ServiceWorkerRegistration | undefined> {
  return navigator.serviceWorker.getRegistration(`${consoleBase()}/`);
}

/** Whether this browser is subscribed already. */
export async function pushEnabled(): Promise<boolean> {
  if (!pushSupported() || Notification.permission !== "granted") return false;
  const current = await registration();
  return (await current?.pushManager.getSubscription()) != null;
}

/** Asks for permission and subscribes this browser. */
export async function enablePush(name: string): Promise<boolean> {
  if ((await Notification.requestPermission()) !== "granted") return false;
  const worker = await navigator.serviceWorker.register(`${consoleBase()}/sw.js`, {
    scope: `${consoleBase()}/`,
  });
  await navigator.serviceWorker.ready;
  const { data: key } = await api.GET("/v1/console/push/key");
  if (key === undefined) return false;
  const subscription = await worker.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: serverKey(key.key),
  });
  const json = subscription.toJSON();
  const { response } = await api.POST("/v1/console/push/subscriptions", {
    body: {
      endpoint: subscription.endpoint,
      keys: { p256dh: json.keys?.p256dh ?? "", auth: json.keys?.auth ?? "" },
      name,
    },
  });
  if (!response.ok) await subscription.unsubscribe();
  return response.ok;
}

/** Unsubscribes this browser. */
export async function disablePush(): Promise<void> {
  const subscription = await (await registration())?.pushManager.getSubscription();
  if (subscription == null) return;
  await api.DELETE("/v1/console/push/subscriptions", { body: { endpoint: subscription.endpoint } });
  await subscription.unsubscribe();
}
