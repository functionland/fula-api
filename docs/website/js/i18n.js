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

    // Inject required CSS for language selector
    function injectStyles() {
        if (document.getElementById('i18n-styles')) return;
        const style = document.createElement('style');
        style.id = 'i18n-styles';
        style.textContent = `
            .language-selector {
                position: relative;
                display: inline-block;
                margin-right: 12px;
            }
            .language-selector-btn {
                display: flex;
                align-items: center;
                gap: 6px;
                padding: 8px 12px;
                background: var(--bg-code, #1e2430);
                border: 1px solid var(--border-color, #30363d);
                border-radius: 8px;
                color: var(--text-primary, #c9d1d9);
                cursor: pointer;
                font-size: 0.9rem;
                font-family: inherit;
                transition: all 0.2s ease;
            }
            .language-selector-btn:hover {
                background: var(--bg-sidebar, #161b22);
                border-color: var(--accent-blue, #58a6ff);
            }
            .language-icon { font-size: 1.1rem; }
            .language-arrow { 
                font-size: 0.65rem; 
                opacity: 0.6; 
                transition: transform 0.2s ease;
                margin-left: 2px;
            }
            .language-selector.open .language-arrow { 
                transform: rotate(180deg); 
            }
            .language-dropdown {
                position: absolute;
                top: calc(100% + 6px);
                left: 0;
                background: var(--bg-sidebar, #161b22);
                border: 1px solid var(--border-color, #30363d);
                border-radius: 10px;
                box-shadow: 0 12px 32px rgba(0,0,0,0.4);
                min-width: 200px;
                max-height: 400px;
                overflow-y: auto;
                opacity: 0;
                visibility: hidden;
                transform: translateY(-8px) scale(0.96);
                transition: all 0.2s ease;
                z-index: 9999;
            }
            .language-selector.open .language-dropdown {
                opacity: 1;
                visibility: visible;
                transform: translateY(0) scale(1);
            }
            .language-option {
                display: flex;
                align-items: center;
                gap: 10px;
                width: 100%;
                padding: 12px 16px;
                background: transparent;
                border: none;
                color: var(--text-primary, #c9d1d9);
                cursor: pointer;
                text-align: left;
                font-size: 0.9rem;
                font-family: inherit;
                transition: background 0.15s ease;
            }
            .language-option:first-child { border-radius: 9px 9px 0 0; }
            .language-option:last-child { border-radius: 0 0 9px 9px; }
            .language-option:hover {
                background: var(--bg-code, #1e2430);
            }
            .language-option.active {
                background: rgba(88, 166, 255, 0.15);
                color: var(--accent-blue, #58a6ff);
            }
            .language-option .lang-flag { font-size: 1.2rem; }
            .language-option .lang-info { 
                display: flex; 
                flex-direction: column; 
                gap: 2px;
            }
            .language-option .lang-native {
                font-weight: 500;
                font-size: 0.9rem;
            }
            .language-option .lang-english {
                font-size: 0.75rem;
                color: var(--text-secondary, #8b949e);
            }
            .language-option.active .lang-english {
                color: var(--accent-blue, #58a6ff);
                opacity: 0.7;
            }
            .language-option .lang-check {
                margin-left: auto;
                opacity: 0;
                color: var(--accent-blue, #58a6ff);
            }
            .language-option.active .lang-check { opacity: 1; }
            
            /* RTL Support */
            html[dir="rtl"] body { direction: rtl; }
            html[dir="rtl"] .sidebar { 
                left: auto; 
                right: 0; 
                border-right: none; 
                border-left: 1px solid var(--border-color, #30363d); 
            }
            html[dir="rtl"] .content { margin-left: 0; margin-right: 280px; }
            html[dir="rtl"] .nav-section li a { 
                border-left: none; 
                border-right: 3px solid transparent; 
                padding-left: 20px; 
                padding-right: 17px; 
            }
            html[dir="rtl"] .nav-section li a.active { border-right-color: var(--accent-blue, #58a6ff); }
            html[dir="rtl"] .language-dropdown { left: auto; right: 0; }
            html[dir="rtl"] .language-option { text-align: right; flex-direction: row-reverse; }
            html[dir="rtl"] .language-option .lang-check { margin-left: 0; margin-right: auto; }
            
            @media (max-width: 768px) {
                html[dir="rtl"] .content { margin-right: 0; }
                html[dir="rtl"] .sidebar { transform: translateX(100%); }
                html[dir="rtl"] .sidebar.open { transform: translateX(0); }
                .language-selector-btn .language-selector-current { display: none; }
                .language-selector-btn .language-arrow { display: none; }
            }
        `;
        document.head.appendChild(style);
    }

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
        injectStyles();
        
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
