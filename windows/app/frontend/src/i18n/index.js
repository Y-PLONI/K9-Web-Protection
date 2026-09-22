// Flat, dot-namespaced keys; `.mac`/`.win` suffixes act as platform variants.

import en from './en.json'
import he from './he.json'

const LOCALES = { en, he }
const STORAGE_KEY = 'k10.lang'
const FALLBACK_LANG = 'en'
const RTL_LANGS = ['he']

// In the Wails WebView navigator.language reflects the OS language; "iw" is the legacy Hebrew code.
export function detectLang() {
  let tag = ''
  try {
    tag = String(navigator.language || '')
  } catch (e) { /* navigator unavailable */ }
  const base = tag.toLowerCase().split('-')[0]
  return base === 'he' || base === 'iw' ? 'he' : FALLBACK_LANG
}

let current = FALLBACK_LANG

function platformSuffix() {
  return window.APP_PLATFORM === 'win' ? 'win' : 'mac'
}

function lookup(table, key) {
  if (!table) return undefined
  const variant = table[key + '.' + platformSuffix()]
  if (typeof variant === 'string') return variant
  const plain = table[key]
  return typeof plain === 'string' ? plain : undefined
}

function interpolate(str, vars) {
  if (!vars) return str
  return str.replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match
  )
}

export function t(key, vars) {
  if (typeof key !== 'string' || !key) return ''
  let value = lookup(LOCALES[current], key)
  if (value === undefined && current !== 'en') value = lookup(LOCALES.en, key)
  if (value === undefined) {
    console.warn('[i18n] missing translation key: ' + key)
    return key
  }
  return interpolate(value, vars)
}

export function getLang() {
  return current
}

export function setLang(lang) {
  current = Object.prototype.hasOwnProperty.call(LOCALES, lang) ? lang : FALLBACK_LANG
  try {
    localStorage.setItem(STORAGE_KEY, current)
  } catch (e) { /* storage unavailable */ }
  const html = document.documentElement
  if (html) {
    html.lang = current
    html.dir = RTL_LANGS.indexOf(current) !== -1 ? 'rtl' : 'ltr'
  }
  return current
}

export function initI18n() {
  let stored = null
  try {
    stored = localStorage.getItem(STORAGE_KEY)
  } catch (e) { /* storage unavailable */ }
  // An explicit stored choice always wins over the environment.
  return setLang(stored && Object.prototype.hasOwnProperty.call(LOCALES, stored) ? stored : detectLang())
}

const ATTR_BINDINGS = [
  ['data-i18n-placeholder', 'placeholder'],
  ['data-i18n-title', 'title'],
  ['data-i18n-aria-label', 'aria-label'],
  ['data-i18n-value', 'value'],
]

function collect(root, selector) {
  const found = []
  if (root.nodeType === 1 && typeof root.matches === 'function' && root.matches(selector)) found.push(root)
  if (typeof root.querySelectorAll === 'function') {
    root.querySelectorAll(selector).forEach(el => found.push(el))
  }
  return found
}

// Idempotent.
export function applyI18n(root = document) {
  if (!root) return
  collect(root, '[data-i18n]').forEach(el => {
    el.textContent = t(el.getAttribute('data-i18n'))
  })
  for (const [attr, target] of ATTR_BINDINGS) {
    collect(root, '[' + attr + ']').forEach(el => {
      el.setAttribute(target, t(el.getAttribute(attr)))
    })
  }
}
