// Shared bilingual (EN / 中文) toggle for Callsign doc pages.
// Elements with data-en / data-zh attributes get their innerHTML swapped.
(function () {
  let lang = localStorage.getItem('callsign-lang');
  if (!['en', 'zh'].includes(lang)) {
    const prefs = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || ''];
    lang = 'en';
    for (const p of prefs) {
      const tag = (p || '').toLowerCase();
      if (tag.startsWith('zh')) { lang = 'zh'; break; }
      if (tag.startsWith('en')) { lang = 'en'; break; }
    }
  }

  function applyLang(l) {
    lang = l;
    document.documentElement.lang = l === 'zh' ? 'zh-CN' : 'en';
    document.querySelectorAll('[data-en]').forEach(function (el) {
      const val = el.getAttribute('data-' + l);
      if (val != null) el.innerHTML = val;
    });
    localStorage.setItem('callsign-lang', l);
  }

  function toggleLang() { applyLang(lang === 'zh' ? 'en' : 'zh'); }

  window.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('[data-lang-toggle]').forEach(function (btn) {
      btn.addEventListener('click', toggleLang);
    });
    applyLang(lang);
  });
})();
