// KeyLease Console service worker: shows a notification when a node reports a
// new pending approval (Web Push, ADR 0011). It caches nothing.
"use strict";

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = {};
  }
  const vi = (self.navigator.language || "").toLowerCase().startsWith("vi");
  const agent = data.agent || (vi ? "Một agent" : "An agent");
  const action = data.action || (vi ? "một thao tác" : "an action");
  const node = data.node || "KeyLease";
  let body = vi ? `${agent} muốn ${action} trên ${node}` : `${agent} wants ${action} on ${node}`;
  if (data.count > 1) {
    body += vi ? ` (và ${data.count - 1} yêu cầu khác)` : ` (and ${data.count - 1} more)`;
  }
  const url = new URL("approvals", self.registration.scope).href;
  event.waitUntil(
    self.registration.showNotification(vi ? "KeyLease: cần duyệt" : "KeyLease: approval needed", {
      body,
      tag: "keylease-approvals",
      renotify: true,
      requireInteraction: true,
      data: { url },
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = event.notification.data && event.notification.data.url;
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => {
      for (const client of windows) {
        if (client.url.startsWith(self.registration.scope) && "focus" in client) {
          return client.navigate(url).then((opened) => (opened || client).focus());
        }
      }
      return self.clients.openWindow(url);
    }),
  );
});
