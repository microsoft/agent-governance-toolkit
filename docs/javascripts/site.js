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

  // Mobile/tablet drawer (< 76.25em): Material renders each top-level section
  // as a <label> that slides to a nested child panel. We collapse that into a
  // single flat list of top-level sections (GitHub-style) — CSS hides the
  // nested panels, and here we point each top-level row straight at that
  // section's landing page so a tap navigates instead of expanding a sub-panel.
  // Desktop (tabs + sections) is untouched.
  var DRAWER_MAX_WIDTH = 1219; // 76.25em at a 16px base, minus 1px.

  function annotateDrawerNavTargets() {
    var primary = document.querySelector('.md-sidebar--primary .md-nav--primary');
    if (!primary) {
      return;
    }
    var items = primary.querySelectorAll(':scope > .md-nav__list > .md-nav__item');
    items.forEach(function (li) {
      var top = li.querySelector(':scope > .md-nav__link');
      if (!top) {
        return;
      }
      var href = top.tagName === 'A' ? top.getAttribute('href') : null;
      if (!href) {
        // Nested section: use its first descendant page as the landing target,
        // dropping any in-page hash so we land at the top of that page.
        var firstLink = li.querySelector('.md-nav a.md-nav__link[href]');
        if (firstLink) {
          try {
            var url = new URL(firstLink.href, window.location.href);
            url.hash = '';
            href = url.pathname + url.search;
          } catch (e) {
            href = firstLink.getAttribute('href');
          }
        }
      }
      if (href) {
        li.dataset.agtFlatHref = href;
      }
    });
  }

  var drawerNavClickWired = false;
  function wireDrawerFlatNav() {
    annotateDrawerNavTargets();
    if (drawerNavClickWired) {
      return;
    }
    drawerNavClickWired = true;
    // Capture phase so we intercept the <label> before Material toggles the
    // (now hidden) nested panel checkbox.
    document.addEventListener(
      'click',
      function (event) {
        if (window.innerWidth > DRAWER_MAX_WIDTH) {
          return; // Desktop keeps Material's native sidebar behavior.
        }
        var link = event.target.closest(
          '.md-sidebar--primary .md-nav--primary > .md-nav__list > .md-nav__item > .md-nav__link'
        );
        if (!link) {
          return;
        }
        var li = link.parentElement;
        if (!li || !li.classList.contains('md-nav__item--nested')) {
          return; // Plain <a> rows already navigate on their own.
        }
        var href = li.dataset.agtFlatHref;
        if (href) {
          event.preventDefault();
          event.stopPropagation();
          window.location.href = href;
        }
      },
      true
    );
  }

  function applyTweaks() {
    applySearchPlaceholder();
    wireTitleHomeLink();
    wireDrawerFlatNav();
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
