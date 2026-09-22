// K9 Web Protection — Blocked page

// Social domain → key map (mirrors SOCIAL_SITES in background.js)
const SOCIAL_SITES_MAP = {
  facebook:  ['facebook.com', 'fb.com', 'messenger.com', 'facebook.net'],
  instagram: ['instagram.com'],
  twitter:   ['twitter.com', 'x.com', 't.co'],
  reddit:    ['reddit.com', 'redd.it'],
  tiktok:    ['tiktok.com', 'tiktokv.com'],
  youtube:   ['youtube.com', 'youtu.be', 'youtube-nocookie.com'],
  snapchat:  ['snapchat.com'],
  pinterest: ['pinterest.com', 'pin.it'],
  linkedin:  ['linkedin.com'],
}

// Flat list for quick isSocial check
const SOCIAL_DOMAINS = Object.values(SOCIAL_SITES_MAP).flat()

// Quotes live in _locales as blocked_quote_1 … blocked_quote_10.
const QUOTE_COUNT = 10

function el(id) { return document.getElementById(id) }

function isSocial(host) {
  return SOCIAL_DOMAINS.some(d => host === d || host.endsWith('.' + d))
}

// Returns the social key for a host, or null
function getSocialKey(host) {
  host = host.toLowerCase().replace(/^www\./, '')
  for (const [key, domains] of Object.entries(SOCIAL_SITES_MAP)) {
    if (domains.some(d => host === d || host.endsWith('.' + d))) return key
  }
  return null
}

// ── Parse params ──────────────────────────────────────────────────────────────
const params     = new URLSearchParams(location.search)
const blockedURL = params.get('url') || ''

let blockedHost = ''
try { blockedHost = new URL(blockedURL).hostname.toLowerCase() } catch (_) {}

const reason = params.get('reason') ||
  (isSocial(blockedHost) ? 'social' : 'adult')

// ── Configure page content ────────────────────────────────────────────────────
if (blockedHost) el('domain').textContent = blockedHost

const quoteIndex = Math.floor(Math.random() * QUOTE_COUNT) + 1

// Styling applies now; the strings wait for the locale catalog.
if (reason === 'social') {
  document.body.classList.add('social')
  el('icon').textContent  = '📵'
  el('quote').style.display = 'block'
} else if (reason === 'keyword') {
  el('icon').textContent = '🔑'
}

function applyReasonText() {
  if (reason === 'social') {
    document.title = k9t('blocked_page_title_social')
    k9i18n.setText(el('title'), 'blocked_title_social')
    k9i18n.setText(el('message'), 'blocked_message_social')
    el('quote').textContent = '"' + k9t('blocked_quote_' + quoteIndex) + '"'
  } else if (reason === 'keyword') {
    k9i18n.setText(el('title'), 'blocked_title_keyword')
    k9i18n.setText(el('message'), 'blocked_message_keyword')
  } else {
    k9i18n.setText(el('message'), 'blocked_message_default')
  }
}

k9i18n.ready.then(applyReasonText).catch(e => console.error('K9 blocked i18n error:', e))
k9i18n.onChange(applyReasonText)

// ── Allow this site ───────────────────────────────────────────────────────────
async function allowSite() {
  if (!blockedHost) return
  const btn = el('btn-allow')
  btn.textContent = k9t('blocked_btn_adding')
  btn.disabled    = true

  try {
    // 1. Update allowlist in storage
    const data = await chrome.storage.local.get('userAllowlist')
    const list  = data.userAllowlist || []
    if (!list.includes(blockedHost)) list.push(blockedHost)
    await chrome.storage.local.set({ userAllowlist: list })

    // 2. If this is a social media site, also turn off its individual toggle
    //    so the popup shows it as disabled when next opened.
    const socialKey = getSocialKey(blockedHost)
    if (socialKey) {
      const { blockSocial = {} } = await chrome.storage.local.get('blockSocial')
      if (blockSocial[socialKey]) {
        blockSocial[socialKey] = false
        await chrome.storage.local.set({ blockSocial })
      }
    }

    // 3. Add allow rule directly for immediate effect
    const existing = await chrome.declarativeNetRequest.getDynamicRules()
    const maxId    = existing.length ? Math.max(...existing.map(r => r.id)) : 20000
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [{
        id:       maxId + 1,
        priority: 10,
        action:   { type: 'allow' },
        condition: { urlFilter: `||${blockedHost}`, resourceTypes: ['main_frame'] },
      }],
    })

    // 4. Tell background to do a full sync so changes persist
    chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings: { userAllowlist: list } })

    // 5. Navigate to the originally blocked URL
    window.location.href = blockedURL || '/'
  } catch (e) {
    console.error('K9 allowSite error:', e)
    btn.textContent = k9t('blocked_btn_error')
    btn.disabled    = false
  }
}

// ── Bind buttons ──────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  el('btn-back').addEventListener('click',  () => history.back())
  el('btn-allow').addEventListener('click', allowSite)
})
