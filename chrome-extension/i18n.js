// K9 Web Protection — i18n runtime; reads _locales directly so the language is a stored preference, not the browser UI locale.

;(function () {
  'use strict'

  const STORAGE_KEY   = 'k9.lang'
  const DEFAULT_LANG  = 'en' // last-resort fallback when no stored pref and browser UI language isn't supported
  const FALLBACK_LANG = 'en'
  const SUPPORTED     = ['en', 'he']            // must match the _locales folders
  const LANG_ALIASES  = { iw: 'he', in: 'id' }  // legacy codes Chrome may report
  const RTL_LANGUAGES = ['he', 'iw', 'ar', 'fa', 'ur', 'yi', 'ji', 'dv', 'ps', 'ckb', 'sd', 'ug']

  let activeLang = ''
  let catalog    = null
  let fallback   = null
  const listeners = []

  function normalize(tag) {
    const base = String(tag || '').toLowerCase().split(/[-_]/)[0]
    return LANG_ALIASES[base] || base
  }

  function isSupported(lang) {
    return SUPPORTED.indexOf(lang) !== -1
  }

  function uiLang() {
    try { return normalize(chrome.i18n.getUILanguage()) } catch (e) { return '' }
  }

  function resolveLang(stored) {
    const wanted = normalize(stored)
    if (isSupported(wanted)) return wanted
    const ui = uiLang()
    if (isSupported(ui)) return ui
    return DEFAULT_LANG
  }

  // localStorage mirror; chrome.storage.local stays the source of truth.
  function readCachedLang() {
    try { return normalize(window.localStorage.getItem(STORAGE_KEY)) } catch (e) { return '' }
  }

  function writeCachedLang(lang) {
    try { window.localStorage.setItem(STORAGE_KEY, lang) } catch (e) { }
  }

  function storageGet(key) {
    return new Promise(function (resolve) {
      try {
        chrome.storage.local.get(key, function (data) {
          if (chrome.runtime.lastError) { resolve(undefined); return }
          resolve((data || {})[key])
        })
      } catch (e) { resolve(undefined) }
    })
  }

  function storageSet(key, value) {
    return new Promise(function (resolve) {
      try {
        const patch = {}
        patch[key] = value
        chrome.storage.local.set(patch, function () {
          void chrome.runtime.lastError
          resolve()
        })
      } catch (e) { resolve() }
    })
  }

  function loadCatalog(lang) {
    let url
    try { url = chrome.runtime.getURL('_locales/' + lang + '/messages.json') }
    catch (e) { return Promise.resolve(null) }
    return fetch(url)
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status)
        return r.json()
      })
      .catch(function () { return null })
  }

  function entryFor(key) {
    if (catalog && Object.prototype.hasOwnProperty.call(catalog, key)) return catalog[key]
    if (fallback && Object.prototype.hasOwnProperty.call(fallback, key)) return fallback[key]
    return null
  }

  // Chrome's $$ / $1..$9 / $name$ rules, which a manual catalog lookup does not get for free.
  function substitute(message, entry, substitutions) {
    if (!message) return ''
    let subs = []
    if (substitutions !== undefined && substitutions !== null) {
      subs = Array.isArray(substitutions) ? substitutions : [substitutions]
    }
    const positional = function (text) {
      return String(text).replace(/\$(\$|[1-9])/g, function (m, c) {
        if (c === '$') return '$'
        const i = Number(c) - 1
        return i < subs.length && subs[i] !== undefined && subs[i] !== null ? String(subs[i]) : ''
      })
    }
    const placeholders = entry && entry.placeholders
    let out = message
    if (placeholders) {
      out = out.replace(/\$([A-Za-z0-9_@]+)\$/g, function (m, name) {
        let def = placeholders[name]
        if (!def) {
          const lower = name.toLowerCase()
          for (const p in placeholders) {
            if (p.toLowerCase() === lower) { def = placeholders[p]; break }
          }
        }
        if (!def || typeof def.content !== 'string') return m
        return positional(def.content)
      })
    }
    return positional(out)
  }

  function getMessage(key, substitutions) {
    if (!key) return ''
    const entry = entryFor(key)
    if (entry && typeof entry.message === 'string') {
      return substitute(entry.message, entry, substitutions)
    }
    // No catalog yet, or the fetch failed.
    try { return chrome.i18n.getMessage(key, substitutions) || '' } catch (e) { return '' }
  }

  function isRTL(lang) {
    const base = normalize(lang || activeLang || uiLang() || DEFAULT_LANG)
    return RTL_LANGUAGES.indexOf(base) !== -1
  }

  function applyDocumentLocale() {
    const html = document.documentElement
    if (!html) return
    const lang = activeLang || readCachedLang() || uiLang() || DEFAULT_LANG
    html.lang = lang
    html.dir = isRTL(lang) ? 'rtl' : 'ltr'
  }

  const ATTRIBUTE_TARGETS = [
    ['data-i18n-placeholder', 'placeholder'],
    ['data-i18n-title', 'title'],
    ['data-i18n-aria-label', 'aria-label'],
    ['data-i18n-alt', 'alt'],
  ]

  function apply(root) {
    const scope = root || document
    scope.querySelectorAll('[data-i18n]').forEach(function (node) {
      const text = getMessage(node.getAttribute('data-i18n'))
      if (text) node.textContent = text
    })
    ATTRIBUTE_TARGETS.forEach(function (pair) {
      scope.querySelectorAll('[' + pair[0] + ']').forEach(function (node) {
        const text = getMessage(node.getAttribute(pair[0]))
        if (text) node.setAttribute(pair[1], text)
      })
    })
  }

  // Remembers the key, so a later apply() keeps the node translated.
  function setText(node, key, substitutions) {
    if (!node) return
    node.setAttribute('data-i18n', key)
    const text = getMessage(key, substitutions)
    if (text) node.textContent = text
  }

  // Unmanage a node that now shows literal data such as a hostname.
  function clearText(node) {
    if (node) node.removeAttribute('data-i18n')
  }

  function notify() {
    listeners.forEach(function (fn) {
      try { fn(activeLang) } catch (e) { console.warn('K9 i18n listener error:', e) }
    })
  }

  function onChange(fn) {
    if (typeof fn === 'function') listeners.push(fn)
  }

  function setLanguage(lang) {
    const next = isSupported(normalize(lang)) ? normalize(lang) : DEFAULT_LANG
    return loadCatalog(next).then(function (cat) {
      activeLang = next
      catalog = cat
      writeCachedLang(next)
      return storageSet(STORAGE_KEY, next)
    }).then(function () {
      applyDocumentLocale()
      apply()
      notify()
      return activeLang
    })
  }

  // Synchronous guess so <html dir> is right on the first paint.
  const cachedLang = readCachedLang()
  activeLang = isSupported(cachedLang) ? cachedLang : resolveLang('')
  applyDocumentLocale()

  const ready = storageGet(STORAGE_KEY).then(function (stored) {
    activeLang = resolveLang(stored)
    writeCachedLang(activeLang)
    applyDocumentLocale()
    if (normalize(stored) !== activeLang) return storageSet(STORAGE_KEY, activeLang)
  }).then(function () {
    return Promise.all([
      loadCatalog(activeLang),
      activeLang === FALLBACK_LANG ? Promise.resolve(null) : loadCatalog(FALLBACK_LANG),
    ])
  }).then(function (loaded) {
    catalog  = loaded[0]
    fallback = loaded[1] || (activeLang === FALLBACK_LANG ? loaded[0] : null)
    applyDocumentLocale()
    apply()
    return activeLang
  }).catch(function (e) {
    console.warn('K9 i18n init failed, falling back to chrome.i18n:', e)
    applyDocumentLocale()
    apply()
    return activeLang || FALLBACK_LANG
  }).then(function (lang) {
    // Reveal the page now that data-i18n nodes hold their final text (success or fallback alike)
    if (document.documentElement) document.documentElement.classList.add('k9i18n-ready')
    return lang
  })

  window.k9t = getMessage
  window.k9i18n = {
    ready: ready,
    t: getMessage,
    apply: apply,
    setText: setText,
    clearText: clearText,
    isRTL: isRTL,
    onChange: onChange,
    setLanguage: setLanguage,
    getLanguage: function () { return activeLang || readCachedLang() || DEFAULT_LANG },
    getSupportedLanguages: function () { return SUPPORTED.slice() },
    applyDocumentLocale: applyDocumentLocale,
  }

  function domPass() {
    apply()
    ready.then(function () { apply() })
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', domPass)
  } else {
    domPass()
  }
})()
