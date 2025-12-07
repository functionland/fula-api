// Fula API Documentation - Interactive Features

document.addEventListener('DOMContentLoaded', () => {
    // Initialize theme
    initTheme();
    
    // Initialize syntax highlighting
    if (typeof hljs !== 'undefined') {
        hljs.highlightAll();
    }
    
    // Initialize navigation highlighting
    initNavHighlight();
    
    // Initialize copy buttons
    initCopyButtons();
    
    // Initialize mobile menu
    initMobileMenu();
});

/**
 * Theme Toggle Functionality
 */
function initTheme() {
    // Get saved theme or default to dark
    const savedTheme = localStorage.getItem('fula-docs-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    
    // Apply code theme on load
    updateCodeTheme(savedTheme);
    
    // Add click handlers to all theme toggles
    document.querySelectorAll('.theme-toggle').forEach(toggle => {
        toggle.addEventListener('click', toggleTheme);
    });
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('fula-docs-theme', newTheme);
    
    // Update highlight.js theme
    updateCodeTheme(newTheme);
}

function updateCodeTheme(theme) {
    // Update highlight.js stylesheet
    const hljsLink = document.querySelector('link[href*="highlight.js"]');
    if (hljsLink) {
        if (theme === 'light') {
            hljsLink.href = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css';
        } else {
            hljsLink.href = 'https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css';
        }
    }
    
    // Re-highlight code blocks when theme changes
    if (typeof hljs !== 'undefined') {
        document.querySelectorAll('pre code').forEach(block => {
            hljs.highlightElement(block);
        });
    }
}

/**
 * Highlight current section in navigation
 */
function initNavHighlight() {
    const sections = document.querySelectorAll('section[id]');
    const navLinks = document.querySelectorAll('.nav-section a');
    
    const observerOptions = {
        root: null,
        rootMargin: '-20% 0px -70% 0px',
        threshold: 0
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const id = entry.target.getAttribute('id');
                navLinks.forEach(link => {
                    link.classList.remove('active');
                    if (link.getAttribute('href') === `#${id}`) {
                        link.classList.add('active');
                    }
                });
            }
        });
    }, observerOptions);
    
    sections.forEach(section => observer.observe(section));
}

/**
 * Copy code to clipboard
 */
function initCopyButtons() {
    document.querySelectorAll('.copy-btn').forEach(btn => {
        btn.addEventListener('click', () => copyCode(btn));
    });
}

function copyCode(button) {
    const codeBlock = button.closest('.example-header').nextElementSibling;
    const code = codeBlock.querySelector('code');
    
    if (code) {
        const text = code.textContent;
        navigator.clipboard.writeText(text).then(() => {
            const originalText = button.textContent;
            button.textContent = 'Copied!';
            button.classList.add('copied');
            
            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('copied');
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy:', err);
        });
    }
}

/**
 * Mobile menu toggle
 */
function initMobileMenu() {
    const sidebar = document.querySelector('.sidebar');
    const hamburger = document.querySelector('.hamburger');
    const overlay = document.querySelector('.sidebar-overlay');
    
    if (!hamburger || !sidebar) return;
    
    // Toggle sidebar
    hamburger.addEventListener('click', () => {
        hamburger.classList.toggle('active');
        sidebar.classList.toggle('open');
        if (overlay) overlay.classList.toggle('active');
        document.body.style.overflow = sidebar.classList.contains('open') ? 'hidden' : '';
    });
    
    // Close sidebar when clicking overlay
    if (overlay) {
        overlay.addEventListener('click', () => {
            hamburger.classList.remove('active');
            sidebar.classList.remove('open');
            overlay.classList.remove('active');
            document.body.style.overflow = '';
        });
    }
    
    // Close sidebar when clicking a link on mobile
    sidebar.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', () => {
            if (window.innerWidth <= 768) {
                hamburger.classList.remove('active');
                sidebar.classList.remove('open');
                if (overlay) overlay.classList.remove('active');
                document.body.style.overflow = '';
            }
        });
    });
    
    // Handle resize
    window.addEventListener('resize', () => {
        if (window.innerWidth > 768) {
            hamburger.classList.remove('active');
            sidebar.classList.remove('open');
            if (overlay) overlay.classList.remove('active');
            document.body.style.overflow = '';
        }
    });
}

/**
 * Smooth scroll to section
 */
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
        }
    });
});

// Add active class styles dynamically
const style = document.createElement('style');
style.textContent = `
    .nav-section li a.active {
        background: rgba(88, 166, 255, 0.15);
        color: #58a6ff;
        border-left-color: #58a6ff;
    }
    
    .sidebar.open {
        transform: translateX(0) !important;
    }
`;
document.head.appendChild(style);
