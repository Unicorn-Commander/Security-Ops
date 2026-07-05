/* Formatting helpers — dates, relative time, money, casing, ordering. */

export function fmtDate(dt, { time = true } = {}) {
  if (!dt) return '—';
  try {
    const d = new Date(dt);
    const opts = time
      ? { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }
      : { year: 'numeric', month: 'short', day: 'numeric' };
    return d.toLocaleString(undefined, opts);
  } catch { return String(dt); }
}

export function relTime(dt) {
  if (!dt) return '—';
  const d = new Date(dt).getTime();
  if (Number.isNaN(d)) return '—';
  const diff = d - Date.now();
  const abs = Math.abs(diff);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  const units = [
    ['day', 86400000], ['hour', 3600000], ['minute', 60000], ['second', 1000],
  ];
  for (const [unit, ms] of units) {
    if (abs >= ms || unit === 'second') return rtf.format(Math.round(diff / ms), unit);
  }
  return 'just now';
}

export function fmtMoney(v) {
  if (v == null) return '—';
  const n = Number(v);
  if (Number.isNaN(n)) return String(v);
  if (n === 0) return '$0.00';
  return n < 0.01 ? `$${n.toFixed(4)}` : `$${n.toFixed(2)}`;
}

export function fmtNum(v) {
  if (v == null) return '0';
  return Number(v).toLocaleString();
}

export function titleCase(s) {
  if (!s) return '';
  return String(s).replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
export const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

export function sortBySeverity(a, b) {
  return (SEVERITY_RANK[b.severity] ?? -1) - (SEVERITY_RANK[a.severity] ?? -1);
}

export function shortId(id) {
  if (!id) return '';
  const s = String(id);
  return s.length > 12 ? `${s.slice(0, 8)}` : s;
}
