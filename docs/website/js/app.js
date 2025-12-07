// Fula API Documentation - Interactive Features

document.addEventListener('DOMContentLoaded', () => {
    // Initialize syntax highlighting
    hljs.highlightAll();
    
    // Initialize navigation highlighting
    initNavHighlight();
    
    // Initialize copy buttons
    initCopyButtons();
    
    // Initialize mobile menu
    initMobileMenu();
});

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
    // Create mobile menu button
    const menuBtn = document.createElement('button');
    menuBtn.className = 'mobile-menu-btn';
    menuBtn.innerHTML = '☰';
    menuBtn.style.cssText = `
        display: none;
        position: fixed;
        top: 20px;
        left: 20px;
        z-index: 200;
        background: var(--bg-sidebar);
        border: 1px solid var(--border-color);
        color: var(--text-primary);
        padding: 10px 15px;
        border-radius: 6px;
        font-size: 1.2rem;
        cursor: pointer;
    `;
    
    document.body.appendChild(menuBtn);
    
    const sidebar = document.querySelector('.sidebar');
    
    // Show menu button on mobile
    const mediaQuery = window.matchMedia('(max-width: 768px)');
    
    function handleScreenChange(e) {
        menuBtn.style.display = e.matches ? 'block' : 'none';
    }
    
    mediaQuery.addListener(handleScreenChange);
    handleScreenChange(mediaQuery);
    
    // Toggle sidebar
    menuBtn.addEventListener('click', () => {
        sidebar.classList.toggle('open');
    });
    
    // Close sidebar when clicking a link on mobile
    sidebar.querySelectorAll('a').forEach(link => {
        link.addEventListener('click', () => {
            if (mediaQuery.matches) {
                sidebar.classList.remove('open');
            }
        });
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
