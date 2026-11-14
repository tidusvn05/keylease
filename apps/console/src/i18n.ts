import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import { en } from "@/locales/en";
import { vi } from "@/locales/vi";

export const languages = ["en", "vi"] as const;
export type Language = (typeof languages)[number];

const STORAGE_KEY = "keylease.console.lang";

function initialLanguage(): Language {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "en" || saved === "vi") return saved;
  } catch {
    // Storage may be blocked; fall back to the browser language.
  }
  return navigator.language.toLowerCase().startsWith("vi") ? "vi" : "en";
}

export function setLanguage(lang: Language) {
  void i18n.changeLanguage(lang);
  document.documentElement.lang = lang;
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // Not persisted; the choice still applies to this tab.
  }
}

void i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, vi: { translation: vi } },
  lng: initialLanguage(),
  fallbackLng: "en",
  interpolation: { escapeValue: false },
});
document.documentElement.lang = i18n.language;

export default i18n;
