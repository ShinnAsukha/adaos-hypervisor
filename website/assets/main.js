/* OXware Hypervisor — main.js */
'use strict';

// Mobile nav toggle
const navToggle = document.getElementById('navToggle');
const navLinks  = document.getElementById('navLinks');
if (navToggle && navLinks) {
    navToggle.addEventListener('click', () => {
        navLinks.classList.toggle('open');
        navToggle.setAttribute('aria-expanded', navLinks.classList.contains('open'));
    });
    // Close on outside click
    document.addEventListener('click', (e) => {
        if (!navToggle.contains(e.target) && !navLinks.contains(e.target)) {
            navLinks.classList.remove('open');
        }
    });
}

// IBAN copy button
document.querySelectorAll('.iban-copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const box = btn.closest('.iban-box');
        const text = box ? box.innerText.replace('Kopyala', '').trim() : '';
        navigator.clipboard.writeText(text).then(() => {
            const orig = btn.textContent;
            btn.textContent = 'Kopyalandı!';
            btn.style.color = '#10b981';
            setTimeout(() => {
                btn.textContent = orig;
                btn.style.color = '';
            }, 2000);
        }).catch(() => {
            // Fallback: select text
            const range = document.createRange();
            range.selectNodeContents(box);
            window.getSelection().removeAllRanges();
            window.getSelection().addRange(range);
        });
    });
});

// Auto-dismiss alerts
document.querySelectorAll('.alert[data-auto-dismiss]').forEach(el => {
    const ms = parseInt(el.dataset.autoDismiss, 10) || 5000;
    setTimeout(() => {
        el.style.transition = 'opacity .4s ease';
        el.style.opacity = '0';
        setTimeout(() => el.remove(), 400);
    }, ms);
});

// Fade-up on scroll (IntersectionObserver)
const fadeEls = document.querySelectorAll('[data-fade]');
if (fadeEls.length && 'IntersectionObserver' in window) {
    const io = new IntersectionObserver((entries) => {
        entries.forEach(e => {
            if (e.isIntersecting) {
                e.target.classList.add('fade-up');
                io.unobserve(e.target);
            }
        });
    }, { threshold: 0.12 });
    fadeEls.forEach(el => {
        el.style.opacity = '0';
        io.observe(el);
    });
}

// Purchase page — show IBAN box on radio select
const payMethodRadios = document.querySelectorAll('input[name="payment_method"]');
const ibanSection     = document.getElementById('ibanSection');
if (payMethodRadios.length && ibanSection) {
    payMethodRadios.forEach(r => {
        r.addEventListener('change', () => {
            ibanSection.style.display = r.value === 'bank_transfer' ? 'block' : 'none';
        });
    });
}
