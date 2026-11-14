export const en = {
  app: { name: "KeyLease Console" },
  nav: {
    overview: "Overview",
    devices: "Devices",
    approvals: "Approvals",
    audit: "Audit log",
  },
  server: {
    checking: "Checking server…",
    online: "Server online",
    offline: "Server unreachable",
    contract: "Contract {{version}}",
  },
  overview: {
    title: "Overview",
    intro: "Manage devices, approvals and the audit log of your KeyLease server.",
  },
  devices: {
    title: "Devices",
    description: "Devices and agents that belong to your account and projects.",
  },
  approvals: {
    title: "Approvals",
    description: "Pending agent requests waiting for a human decision.",
  },
  audit: {
    title: "Audit log",
    description: "Every credential use, approval and trust change.",
  },
  comingSoon: "This page needs the keylease-server API (phase P2). It is not available yet.",
  language: "Language",
  notFound: "Page not found.",
};

export type Messages = typeof en;
