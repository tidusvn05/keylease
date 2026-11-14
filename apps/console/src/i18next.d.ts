import "i18next";
import type { Messages } from "@/locales/en";

declare module "i18next" {
  interface CustomTypeOptions {
    resources: { translation: Messages };
  }
}
