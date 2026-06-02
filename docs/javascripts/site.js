// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Site-level UI tweaks layered on top of the Material theme.

(function () {
  function applySearchPlaceholder() {
    document.querySelectorAll('.md-search__input').forEach(function (input) {
      input.setAttribute('placeholder', 'Search or filter');
      input.setAttribute('aria-label', 'Search or filter');
    });
  }

  // Make the site title part of the home link: Material only links the logo
  // icon, so wire the adjacent title text to navigate to the same href.
  function wireTitleHomeLink() {
    var logo = document.querySelector('.md-header__button.md-logo');
    var title = document.querySelector('.md-header__title');
    if (!logo || !title || title.dataset.homeLinked === 'true') {
      return;
    }
    var href = logo.getAttribute('href');
    if (!href) {
      return;
    }
    title.dataset.homeLinked = 'true';
    title.setAttribute('role', 'link');
    title.setAttribute('tabindex', '0');
    title.addEventListener('click', function () {
      window.location.href = href;
    });
    title.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        window.location.href = href;
      }
    });
  }

  function applyTweaks() {
    applySearchPlaceholder();
    wireTitleHomeLink();
  }

  // Initial paint.
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', applyTweaks);
  } else {
    applyTweaks();
  }

  // Re-apply on Material's instant-navigation page swaps, if available.
  if (typeof window !== 'undefined' && window.document$ && typeof window.document$.subscribe === 'function') {
    window.document$.subscribe(applyTweaks);
  }
})();
