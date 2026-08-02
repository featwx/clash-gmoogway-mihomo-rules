#!/usr/bin/env node
'use strict'

const fs = require('fs')
const vm = require('vm')

const scriptPath = process.argv[2]
if (!scriptPath) throw new Error('usage: apply_script.js <script-path>')

const config = JSON.parse(fs.readFileSync(0, 'utf8'))
const beforeGroups = JSON.stringify(config['proxy-groups'] || [])
const beforeProxies = JSON.stringify(config.proxies || [])
const beforeProviderNames = new Set(
  Object.keys(config['rule-providers'] || {})
)
const beforeRuleCount = (config.rules || []).length

const sandbox = {
  console,
  $arguments: {
    ruleBase: 'https://example.invalid/clash-rules',
    updateInterval: 21600,
  },
}
vm.createContext(sandbox)
vm.runInContext(fs.readFileSync(scriptPath, 'utf8'), sandbox, {
  filename: scriptPath,
})

if (typeof sandbox.main !== 'function') {
  throw new Error('extension script did not define main(config)')
}

const result = sandbox.main(config)
const afterGroups = JSON.stringify(result['proxy-groups'] || [])
const afterProxies = JSON.stringify(result.proxies || [])

if (beforeGroups !== afterGroups) {
  throw new Error('proxy-groups changed')
}
if (beforeProxies !== afterProxies) {
  throw new Error('proxies changed')
}

for (const name of beforeProviderNames) {
  if (!result['rule-providers']?.[name]) {
    throw new Error(`existing rule-provider removed: ${name}`)
  }
}

for (const name of [
  'gmoogway-reject',
  'gmoogway-proxy',
  'gmoogway-direct',
]) {
  if (!result['rule-providers']?.[name]) {
    throw new Error(`missing rule-provider: ${name}`)
  }
}

const addedRules = (result.rules || []).filter((rule) =>
  String(rule).startsWith('RULE-SET,gmoogway-')
)
if (addedRules.length !== 3) {
  throw new Error(`expected 3 GMOogway rules, got ${addedRules.length}`)
}

const firstGenericIndex = result.rules.indexOf('GEOSITE,private,直连')
const lastAddedIndex = Math.max(
  ...addedRules.map((rule) => result.rules.indexOf(rule))
)
if (firstGenericIndex < 0 || lastAddedIndex >= firstGenericIndex) {
  throw new Error('GMOogway rules were not inserted before generic fallbacks')
}

if (result.rules.length !== beforeRuleCount + 3) {
  throw new Error('unexpected rule count change')
}
if (result.dns?.['prefer-h3'] !== false) {
  throw new Error('prefer-h3 must be disabled with respect-rules')
}
if (result.dns?.['fake-ip-filter-mode'] !== 'rule') {
  throw new Error('fake-ip-filter-mode must be rule')
}
if (result.tun?.['strict-route'] !== true) {
  throw new Error('TUN strict-route is not enabled')
}

process.stderr.write(
  JSON.stringify(
    {
      proxyGroupsUnchanged: true,
      proxiesUnchanged: true,
      rulesBefore: beforeRuleCount,
      rulesAfter: result.rules.length,
      addedRules,
      providersAfter: Object.keys(result['rule-providers'] || {}),
      dns: {
        nameserver: result.dns?.nameserver,
        fakeIpFilterMode: result.dns?.['fake-ip-filter-mode'],
        respectRules: result.dns?.['respect-rules'],
        preferH3: result.dns?.['prefer-h3'],
      },
    },
    null,
    2
  ) + '\n'
)
process.stdout.write(JSON.stringify(result))
