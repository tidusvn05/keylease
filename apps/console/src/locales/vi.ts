import type { Messages } from "./en";

export const vi: Messages = {
  app: { name: "KeyLease Console" },
  nav: {
    overview: "Tổng quan",
    devices: "Thiết bị",
    approvals: "Phê duyệt",
    audit: "Nhật ký audit",
  },
  server: {
    checking: "Đang kiểm tra server…",
    online: "Server đang chạy",
    offline: "Không kết nối được server",
    contract: "Contract {{version}}",
  },
  overview: {
    title: "Tổng quan",
    intro: "Quản lý thiết bị, phê duyệt và nhật ký audit của KeyLease server.",
  },
  devices: {
    title: "Thiết bị",
    description: "Các thiết bị và agent thuộc tài khoản và project của bạn.",
  },
  approvals: {
    title: "Phê duyệt",
    description: "Các yêu cầu của agent đang chờ người duyệt.",
  },
  audit: {
    title: "Nhật ký audit",
    description: "Mọi lần dùng credential, phê duyệt và thay đổi trust.",
  },
  comingSoon: "Trang này cần API của keylease-server (giai đoạn P2), hiện chưa có.",
  language: "Ngôn ngữ",
  notFound: "Không tìm thấy trang.",
};
