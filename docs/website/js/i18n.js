// Fula API Documentation - Internationalization (i18n) System
// Languages: English, Chinese, Farsi, Arabic, German, Spanish, Hindi, French

(function() {
    'use strict';

    const SUPPORTED_LANGUAGES = {
        en: { name: 'English', nativeName: 'English', dir: 'ltr', flag: '🇺🇸' },
        zh: { name: 'Chinese', nativeName: '中文', dir: 'ltr', flag: '🇨🇳' },
        fa: { name: 'Farsi', nativeName: 'فارسی', dir: 'rtl', flag: '🇮🇷' },
        ar: { name: 'Arabic', nativeName: 'العربية', dir: 'rtl', flag: '🇸🇦' },
        de: { name: 'German', nativeName: 'Deutsch', dir: 'ltr', flag: '🇩🇪' },
        es: { name: 'Spanish', nativeName: 'Español', dir: 'ltr', flag: '🇪🇸' },
        hi: { name: 'Hindi', nativeName: 'हिन्दी', dir: 'ltr', flag: '🇮🇳' },
        fr: { name: 'French', nativeName: 'Français', dir: 'ltr', flag: '🇫🇷' }
    };

    const STORAGE_KEY = 'fula-docs-language';
    const DEFAULT_LANGUAGE = 'en';

    // CSS is now loaded via css/i18n.css - no injection needed

    class I18n {
        constructor() {
            this.translations = {};
            this.currentLanguage = this.getSavedLanguage() || this.detectBrowserLanguage() || DEFAULT_LANGUAGE;
            this.listeners = [];
            this.initialized = false;
        }
        
        getSavedLanguage() {
            try { 
                const saved = localStorage.getItem(STORAGE_KEY);
                return SUPPORTED_LANGUAGES[saved] ? saved : null;
            } catch (e) { return null; }
        }
        
        detectBrowserLanguage() {
            try {
                const browserLang = (navigator.language || navigator.userLanguage || '').split('-')[0];
                return SUPPORTED_LANGUAGES[browserLang] ? browserLang : null;
            } catch (e) { return null; }
        }
        
        getLanguage() { return this.currentLanguage; }
        getLangInfo() { return SUPPORTED_LANGUAGES[this.currentLanguage]; }
        
        setLanguage(lang) {
            if (!SUPPORTED_LANGUAGES[lang]) lang = DEFAULT_LANGUAGE;
            this.currentLanguage = lang;
            try { localStorage.setItem(STORAGE_KEY, lang); } catch (e) {}
            this.applyLanguage();
            this.updateAllSelectors();
            this.listeners.forEach(cb => cb(lang));
        }
        
        t(key, fallback = null) {
            const t = this.translations[this.currentLanguage];
            if (t && t[key] !== undefined) return t[key];
            const en = this.translations.en;
            if (en && en[key] !== undefined) return en[key];
            return fallback !== null ? fallback : key;
        }
        
        applyLanguage() {
            const langInfo = SUPPORTED_LANGUAGES[this.currentLanguage];
            if (!langInfo) return;
            
            // Set document direction and language
            document.documentElement.setAttribute('lang', this.currentLanguage);
            document.documentElement.setAttribute('dir', langInfo.dir);
            
            // Translate all elements with data-i18n attribute
            document.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.getAttribute('data-i18n');
                const translation = this.t(key);
                if (translation && translation !== key) {
                    if (translation.includes('<') && translation.includes('>')) {
                        el.innerHTML = translation;
                    } else {
                        el.textContent = translation;
                    }
                }
            });
            
            // Translate placeholders
            document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
                const key = el.getAttribute('data-i18n-placeholder');
                const translation = this.t(key);
                if (translation && translation !== key) {
                    el.placeholder = translation;
                }
            });
            
            // Translate title attributes
            document.querySelectorAll('[data-i18n-title]').forEach(el => {
                const key = el.getAttribute('data-i18n-title');
                const translation = this.t(key);
                if (translation && translation !== key) {
                    el.title = translation;
                }
            });
        }
        
        updateAllSelectors() {
            const langInfo = SUPPORTED_LANGUAGES[this.currentLanguage];
            // Update all current language displays
            document.querySelectorAll('.language-selector-current').forEach(el => {
                el.textContent = langInfo.nativeName;
            });
            // Update active states
            document.querySelectorAll('.language-option').forEach(opt => {
                opt.classList.toggle('active', opt.getAttribute('data-lang') === this.currentLanguage);
            });
        }
        
        onLanguageChange(callback) { this.listeners.push(callback); }
        getSupportedLanguages() { return SUPPORTED_LANGUAGES; }
        
        loadTranslations(t) { 
            this.translations = t;
            // Re-apply if already initialized
            if (this.initialized) {
                this.applyLanguage();
            }
        }
    }

    // Create global instance
    const i18n = new I18n();
    window.i18n = i18n;
    window.SUPPORTED_LANGUAGES = SUPPORTED_LANGUAGES;

    function createLanguageSelector() {
        const container = document.createElement('div');
        container.className = 'language-selector';
        
        const currentLang = SUPPORTED_LANGUAGES[i18n.getLanguage()];
        
        container.innerHTML = `
            <button class="language-selector-btn" type="button" aria-label="Select language" aria-haspopup="listbox">
                <span class="language-icon">${currentLang.flag}</span>
                <span class="language-selector-current">${currentLang.nativeName}</span>
                <span class="language-arrow">▼</span>
            </button>
            <div class="language-dropdown" role="listbox">
                ${Object.entries(SUPPORTED_LANGUAGES).map(([code, info]) => `
                    <button type="button" class="language-option ${code === i18n.getLanguage() ? 'active' : ''}" 
                            data-lang="${code}" 
                            role="option"
                            aria-selected="${code === i18n.getLanguage()}">
                        <span class="lang-flag">${info.flag}</span>
                        <span class="lang-info">
                            <span class="lang-native">${info.nativeName}</span>
                            <span class="lang-english">${info.name}</span>
                        </span>
                        <span class="lang-check">✓</span>
                    </button>
                `).join('')}
            </div>
        `;
        
        const btn = container.querySelector('.language-selector-btn');
        const dropdown = container.querySelector('.language-dropdown');
        
        // Toggle dropdown
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            // Close other dropdowns
            document.querySelectorAll('.language-selector.open').forEach(s => {
                if (s !== container) s.classList.remove('open');
            });
            container.classList.toggle('open');
        });
        
        // Handle language selection
        container.querySelectorAll('.language-option').forEach(option => {
            option.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const lang = option.getAttribute('data-lang');
                i18n.setLanguage(lang);
                container.classList.remove('open');
            });
        });
        
        return container;
    }

    function initI18n() {
        // Add selector to sidebar header
        const sidebarHeader = document.querySelector('.sidebar-header');
        if (sidebarHeader && !sidebarHeader.querySelector('.language-selector')) {
            const langSelector = createLanguageSelector();
            const themeToggle = sidebarHeader.querySelector('.theme-toggle');
            if (themeToggle) {
                themeToggle.insertAdjacentElement('beforebegin', langSelector);
            } else {
                sidebarHeader.appendChild(langSelector);
            }
        }
        
        // Add selector to mobile header
        const mobileHeaderActions = document.querySelector('.mobile-header-actions');
        if (mobileHeaderActions && !mobileHeaderActions.querySelector('.language-selector')) {
            const mobileLangSelector = createLanguageSelector();
            mobileHeaderActions.insertBefore(mobileLangSelector, mobileHeaderActions.firstChild);
        }
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.language-selector')) {
                document.querySelectorAll('.language-selector.open').forEach(s => s.classList.remove('open'));
            }
        });
        
        // Close on escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.language-selector.open').forEach(s => s.classList.remove('open'));
            }
        });
        
        i18n.initialized = true;
        i18n.applyLanguage();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initI18n);
    } else {
        initI18n();
    }
})();
