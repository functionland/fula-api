// Fula API Documentation - Internationalization (i18n) System
// Languages: English, Chinese, Farsi, Arabic, German, Spanish, Hindi, French

const SUPPORTED_LANGUAGES = {
    en: { name: 'English', nativeName: 'English', dir: 'ltr' },
    zh: { name: 'Chinese', nativeName: '中文', dir: 'ltr' },
    fa: { name: 'Farsi', nativeName: 'فارسی', dir: 'rtl' },
    ar: { name: 'Arabic', nativeName: 'العربية', dir: 'rtl' },
    de: { name: 'German', nativeName: 'Deutsch', dir: 'ltr' },
    es: { name: 'Spanish', nativeName: 'Español', dir: 'ltr' },
    hi: { name: 'Hindi', nativeName: 'हिन्दी', dir: 'ltr' },
    fr: { name: 'French', nativeName: 'Français', dir: 'ltr' }
};

const STORAGE_KEY = 'fula-docs-language';
const DEFAULT_LANGUAGE = 'en';

class I18n {
    constructor() {
        this.translations = {};
        this.currentLanguage = this.getSavedLanguage() || this.detectBrowserLanguage() || DEFAULT_LANGUAGE;
        this.listeners = [];
    }
    
    getSavedLanguage() {
        try { return localStorage.getItem(STORAGE_KEY); } catch (e) { return null; }
    }
    
    detectBrowserLanguage() {
        const browserLang = (navigator.language || navigator.userLanguage || '').split('-')[0];
        return SUPPORTED_LANGUAGES[browserLang] ? browserLang : null;
    }
    
    getLanguage() { return this.currentLanguage; }
    
    setLanguage(lang) {
        if (!SUPPORTED_LANGUAGES[lang]) lang = DEFAULT_LANGUAGE;
        this.currentLanguage = lang;
        try { localStorage.setItem(STORAGE_KEY, lang); } catch (e) {}
        this.applyLanguage();
        this.listeners.forEach(cb => cb(lang));
    }
    
    t(key, fallback = null) {
        const t = this.translations[this.currentLanguage];
        if (t && t[key]) return t[key];
        if (this.translations.en && this.translations.en[key]) return this.translations.en[key];
        return fallback || key;
    }
    
    applyLanguage() {
        const langInfo = SUPPORTED_LANGUAGES[this.currentLanguage];
        document.documentElement.setAttribute('lang', this.currentLanguage);
        document.documentElement.setAttribute('dir', langInfo.dir);
        document.body.classList.toggle('rtl', langInfo.dir === 'rtl');
        
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            const translation = this.t(key);
            if (translation.includes('<')) el.innerHTML = translation;
            else el.textContent = translation;
        });
        
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            el.placeholder = this.t(el.getAttribute('data-i18n-placeholder'));
        });
        
        const selector = document.querySelector('.language-selector-current');
        if (selector) selector.textContent = langInfo.nativeName;
    }
    
    onLanguageChange(callback) { this.listeners.push(callback); }
    getSupportedLanguages() { return SUPPORTED_LANGUAGES; }
    loadTranslations(t) { this.translations = t; }
}

const i18n = new I18n();

function createLanguageSelector() {
    const selector = document.createElement('div');
    selector.className = 'language-selector';
    selector.innerHTML = `
        <button class="language-selector-btn" aria-label="Select language">
            <span class="language-icon">🌐</span>
            <span class="language-selector-current">${SUPPORTED_LANGUAGES[i18n.getLanguage()].nativeName}</span>
            <span class="language-arrow">▼</span>
        </button>
        <div class="language-dropdown">
            ${Object.entries(SUPPORTED_LANGUAGES).map(([code, info]) => `
                <button class="language-option ${code === i18n.getLanguage() ? 'active' : ''}" 
                        data-lang="${code}" dir="${info.dir}">
                    <span class="lang-native">${info.nativeName}</span>
                    <span class="lang-english">${info.name}</span>
                </button>
            `).join('')}
        </div>
    `;
    
    const btn = selector.querySelector('.language-selector-btn');
    const dropdown = selector.querySelector('.language-dropdown');
    
    btn.addEventListener('click', (e) => { e.stopPropagation(); dropdown.classList.toggle('open'); });
    
    selector.querySelectorAll('.language-option').forEach(option => {
        option.addEventListener('click', (e) => {
            e.stopPropagation();
            i18n.setLanguage(option.getAttribute('data-lang'));
            dropdown.classList.remove('open');
            selector.querySelectorAll('.language-option').forEach(opt => {
                opt.classList.toggle('active', opt.getAttribute('data-lang') === i18n.getLanguage());
            });
        });
    });
    
    document.addEventListener('click', () => dropdown.classList.remove('open'));
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') dropdown.classList.remove('open'); });
    
    return selector;
}

function initI18n() {
    const sidebarHeader = document.querySelector('.sidebar-header');
    if (sidebarHeader) {
        const langSelector = createLanguageSelector();
        const themeToggle = sidebarHeader.querySelector('.theme-toggle');
        if (themeToggle) themeToggle.insertAdjacentElement('beforebegin', langSelector);
        else sidebarHeader.appendChild(langSelector);
    }
    
    const mobileHeaderActions = document.querySelector('.mobile-header-actions');
    if (mobileHeaderActions) {
        const mobileLangSelector = createLanguageSelector();
        mobileLangSelector.classList.add('mobile-lang-selector');
        mobileHeaderActions.insertBefore(mobileLangSelector, mobileHeaderActions.firstChild);
    }
    
    i18n.applyLanguage();
}

// Auto-init when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initI18n);
} else {
    initI18n();
}
