import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import axios from 'axios';
import en from './locales/en.json';
import ko from './locales/ko.json';

const supportedLanguages = ['en', 'ko'] as const;
type SupportedLanguage = typeof supportedLanguages[number];

// Tell the backend which language to render API error messages in, kept
// in lockstep with the active UI locale. Set on boot and on every change
// so it also covers the pre-auth login screen, where there's no account
// yet — GetLanguageFromRequest reads this Accept-Language header.
function syncBackendLanguage(lng: string): void {
  axios.defaults.headers.common['Accept-Language'] = lng;
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      ko: { translation: ko },
    },
    fallbackLng: 'en',
    supportedLngs: [...supportedLanguages],
    // Map region tags from the browser (e.g. "ko-KR", "en-US") onto the
    // base locales we actually ship.
    load: 'languageOnly',
    interpolation: {
      escapeValue: false, // React already escapes by default
    },
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'i18nextLng',
      caches: ['localStorage'],
    },
  });

syncBackendLanguage(i18n.resolvedLanguage || i18n.language || 'en');
i18n.on('languageChanged', (lng) => syncBackendLanguage(lng));

/**
 * Sync language from user account preference.
 * Call this after fetching user data from the backend.
 */
export function setLanguageFromUser(lang?: string): void {
  if (lang && supportedLanguages.includes(lang as SupportedLanguage)) {
    i18n.changeLanguage(lang);
  }
}
