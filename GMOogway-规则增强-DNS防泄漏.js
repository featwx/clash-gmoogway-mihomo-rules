/**
 * Clash Verge Rev / Mihomo additive extension script.
 *
 * Run this AFTER the existing YaNet script. It does not create, remove, or
 * replace any proxy group. It only adds three remote rule-providers, inserts
 * their RULE-SET entries before the generic fallback rules, and hardens DNS.
 */

const integrationDefaults = {
  enable: true,
  ruleBase:
    'https://raw.githubusercontent.com/featwx/clash-gmoogway-mihomo-rules/main/rules',
  updateInterval: 21600,
  directPolicy: '直连',
  proxyPolicy: '其他外网',
  rejectPolicy: '拒绝',
  dnsLeakProtection: true,
  domesticDNS:
    'https://doh.pub/dns-query;https://dns.alidns.com/dns-query',
  foreignDNS: '',
}

const integrationArgs = {
  ...integrationDefaults,
  ...(typeof $arguments === 'object' && $arguments !== null
    ? $arguments
    : {}),
}

function toArray(value) {
  if (Array.isArray(value)) return value.filter(Boolean)
  if (typeof value !== 'string') return []
  return value
    .split(';')
    .map((item) => item.trim())
    .filter(Boolean)
}

function toBoolean(value, fallback) {
  if (typeof value === 'boolean') return value
  if (value === 'true') return true
  if (value === 'false') return false
  return fallback
}

function policyNames(config) {
  const names = new Set()
  for (const group of config?.['proxy-groups'] || []) {
    if (group?.name) names.add(group.name)
  }
  for (const proxy of config?.proxies || []) {
    if (proxy?.name) names.add(proxy.name)
  }
  return names
}

function normalizeRuleBase(value) {
  return String(value || '').trim().replace(/\/+$/, '')
}

function addRuleProviders(config, ruleBase, updateInterval, proxyPolicy) {
  const providers = { ...(config['rule-providers'] || {}) }
  const common = {
    type: 'http',
    behavior: 'classical',
    format: 'text',
    interval: updateInterval,
    proxy: proxyPolicy,
  }

  providers['gmoogway-direct'] = {
    ...common,
    url: `${ruleBase}/sr_direct.list`,
    path: './ruleset/GMOogway-Mihomo/sr_direct.list',
  }
  providers['gmoogway-proxy'] = {
    ...common,
    url: `${ruleBase}/sr_proxy.list`,
    path: './ruleset/GMOogway-Mihomo/sr_proxy.list',
  }
  providers['gmoogway-reject'] = {
    ...common,
    url: `${ruleBase}/sr_reject.list`,
    path: './ruleset/GMOogway-Mihomo/sr_reject.list',
  }

  config['rule-providers'] = providers
}

function addRules(config, directPolicy, proxyPolicy, rejectPolicy) {
  const providerPrefix = 'RULE-SET,gmoogway-'
  const existingRules = (config.rules || []).filter(
    (rule) => typeof rule !== 'string' || !rule.startsWith(providerPrefix)
  )

  const additions = [
    `RULE-SET,gmoogway-reject,${rejectPolicy}`,
    `RULE-SET,gmoogway-proxy,${proxyPolicy}`,
    `RULE-SET,gmoogway-direct,${directPolicy}`,
  ]

  let insertAt = existingRules.findIndex(
    (rule) =>
      rule === `GEOSITE,private,${directPolicy}` ||
      rule === `GEOIP,private,${directPolicy},no-resolve`
  )
  if (insertAt < 0) {
    insertAt = existingRules.findIndex((rule) =>
      String(rule).startsWith('MATCH,')
    )
  }
  if (insertAt < 0) insertAt = existingRules.length

  existingRules.splice(insertAt, 0, ...additions)
  config.rules = existingRules
}

function hardenDNS(config, directPolicy, proxyPolicy, domesticDNSValue, foreignDNSValue) {
  const currentDNS = config.dns || {}
  const domesticDNS = toArray(domesticDNSValue)
  const foreignDNS = toArray(foreignDNSValue)
  const protectedForeignDNS =
    foreignDNS.length > 0
      ? foreignDNS
      : [
          `https://1.1.1.1/dns-query#${proxyPolicy}`,
          `https://8.8.8.8/dns-query#${proxyPolicy}`,
        ]

  const currentPolicy = currentDNS['nameserver-policy'] || {}
  const nameserverPolicy = {}
  const replacedForeignMarkers = [
    'gfw',
    'jetbrains-ai',
    'category-ai-',
    'geolocation-!cn',
  ]

  for (const [key, value] of Object.entries(currentPolicy)) {
    if (!replacedForeignMarkers.some((marker) => key.includes(marker))) {
      nameserverPolicy[key] = value
    }
  }

  nameserverPolicy[
    'geosite:gfw,jetbrains-ai,category-ai-!cn,category-ai-chat-!cn,geolocation-!cn'
  ] = protectedForeignDNS
  nameserverPolicy['geosite:category-remote-control'] = domesticDNS

  config.dns = {
    ...currentDNS,
    enable: true,
    ipv6: false,
    'prefer-h3': false,
    'cache-algorithm': 'arc',
    'respect-rules': true,
    nameserver: protectedForeignDNS,
    'direct-nameserver': domesticDNS,
    'direct-nameserver-follow-policy': true,
    'proxy-server-nameserver': domesticDNS,
    'nameserver-policy': nameserverPolicy,
    'fake-ip-filter-mode': 'rule',
    'fake-ip-filter': [
      'GEOSITE,private,real-ip',
      'GEOSITE,category-public-tracker,real-ip',
      'GEOSITE,category-game-platforms-download@cn,real-ip',
      'GEOSITE,category-remote-control,real-ip',
      'GEOSITE,category-games@cn,real-ip',
      'GEOSITE,jetbrains-ai,fake-ip',
      'GEOSITE,category-ai-!cn,fake-ip',
      'GEOSITE,category-ai-chat-!cn,fake-ip',
      'GEOSITE,category-games-!cn,fake-ip',
      'GEOSITE,category-cdn-!cn,fake-ip',
      'GEOSITE,telegram,fake-ip',
      'GEOSITE,google,fake-ip',
      'GEOSITE,amazon,fake-ip',
      'GEOSITE,category-bank-jp,fake-ip',
      'GEOSITE,category-communication,fake-ip',
      'GEOSITE,gfw,fake-ip',
      'GEOSITE,cn,real-ip',
      'MATCH,fake-ip',
    ],
  }

  if (config.tun && typeof config.tun === 'object') {
    const dnsHijack = new Set(config.tun['dns-hijack'] || [])
    dnsHijack.add('any:53')
    dnsHijack.add('tcp://any:53')
    config.tun = {
      ...config.tun,
      'strict-route': true,
      'dns-hijack': [...dnsHijack],
    }
  }
}

function main(config) {
  if (!toBoolean(integrationArgs.enable, true)) return config

  const directPolicy = String(integrationArgs.directPolicy || '直连')
  const proxyPolicy = String(integrationArgs.proxyPolicy || '其他外网')
  const rejectPolicy = String(integrationArgs.rejectPolicy || '拒绝')
  const availablePolicies = policyNames(config)
  const requiredPolicies = [directPolicy, proxyPolicy, rejectPolicy]
  const missingPolicies = requiredPolicies.filter(
    (name) => !availablePolicies.has(name)
  )

  // A wrong script order must not break the currently working configuration.
  if (missingPolicies.length > 0) {
    if (typeof console !== 'undefined' && console.warn) {
      console.warn(
        `[GMOogway integration] skipped: run after YaNet; missing ${missingPolicies.join(', ')}`
      )
    }
    return config
  }

  const ruleBase = normalizeRuleBase(integrationArgs.ruleBase)
  if (!ruleBase) {
    if (typeof console !== 'undefined' && console.warn) {
      console.warn('[GMOogway integration] skipped: remote rule URL is not configured')
    }
    return config
  }

  const updateInterval = Math.max(
    3600,
    Number(integrationArgs.updateInterval) || 21600
  )

  addRuleProviders(config, ruleBase, updateInterval, proxyPolicy)
  addRules(config, directPolicy, proxyPolicy, rejectPolicy)

  if (toBoolean(integrationArgs.dnsLeakProtection, true)) {
    hardenDNS(
      config,
      directPolicy,
      proxyPolicy,
      integrationArgs.domesticDNS,
      integrationArgs.foreignDNS
    )
  }

  return config
}
