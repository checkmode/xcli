// xcli ww local policy: generated data, regenerated from ww on sync.
const WW_POLICY = __WW_POLICY__;

// Only simple same-action rules are safe to cross while looking for coverage.
// A different action or an unknown rule type is a barrier, even if a broad
// DIRECT rule exists later. Re-evaluate against the fresh subscription each run.
function wwCovered(local, upstream) {
  const wanted = local.split(',');
  const simple = ['DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR'];
  if (!simple.includes(wanted[0])) return false;
  function network(value) {
    const parts = value.split('/');
    if (parts.length !== 2 || !/^\d+$/.test(parts[1])) return null;
    const bits = Number(parts[1]), octets = parts[0].split('.');
    if (bits < 0 || bits > 32 || octets.length !== 4 ||
        octets.some(v => !/^\d+$/.test(v) || Number(v) > 255)) return null;
    const address = octets.reduce((n, v) => n * 256 + Number(v), 0);
    const size = Math.pow(2, 32 - bits);
    return [Math.floor(address / size) * size, size];
  }
  for (const rule of upstream) {
    const parent = rule.split(',');
    if (!simple.includes(parent[0]) || parent[2] !== wanted[2]) return false;
    if (parent[0] === 'IP-CIDR' && (parent.length !== 4 || parent[3] !== 'no-resolve')) return false;
    if (parent[0] !== 'IP-CIDR' && parent.length !== 3) return false;
    if (wanted[0] === 'IP-CIDR' && parent[0] === 'IP-CIDR' &&
        wanted.length === 4 && wanted[3] === 'no-resolve') {
      const a = network(wanted[1]), b = network(parent[1]);
      if (a && b && a[0] >= b[0] && a[0] + a[1] <= b[0] + b[1]) return true;
    }
    if (wanted[0] !== 'IP-CIDR' && parent[0] === 'DOMAIN-SUFFIX' &&
        (wanted[1] === parent[1] || wanted[1].endsWith('.' + parent[1]))) return true;
    if (wanted[0] === 'DOMAIN' && parent[0] === 'DOMAIN' && wanted[1] === parent[1]) return true;
  }
  return false;
}

function main(config) {
  const unique = values => Array.from(new Set(values));
  const upstream = config.rules || [];
  const local = WW_POLICY.rules.filter(rule => !wwCovered(rule, upstream));
  config.rules = unique(local.concat(upstream));
  const dns = config.dns || (config.dns = {});
  // Explicit local domains must precede geosite policies.
  dns['nameserver-policy'] = Object.assign({}, dns['nameserver-policy'] || {}, WW_POLICY.dns);
  const ordered = {};
  for (const key of Object.keys(WW_POLICY.dns)) ordered[key] = WW_POLICY.dns[key];
  for (const key of Object.keys(dns['nameserver-policy'])) ordered[key] = dns['nameserver-policy'][key];
  dns['nameserver-policy'] = ordered;
  if (Object.keys(WW_POLICY.dns).length) dns['direct-nameserver-follow-policy'] = true;
  if (WW_POLICY.filters.length) {
    // A whitelist/rule filter has different semantics; do not silently corrupt it.
    if (dns['fake-ip-filter-mode'] && dns['fake-ip-filter-mode'] !== 'blacklist') {
      throw new Error('ww policy requires blacklist fake-ip-filter-mode');
    }
    dns['fake-ip-filter'] = unique((dns['fake-ip-filter'] || []).concat(WW_POLICY.filters));
  }
  return config;
}
