// Time limits. Every value is read from the environment; 0 or unset = NO limit.
// Example: NEORA_FETCH_MS=120000 brings a limit back for that step.
export const ms = (name, def = 0) => {
  const v = process.env[name];
  if (v === undefined || v === '') return def;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : 0;
};
// AbortSignal for fetch(): undefined when there is no limit.
export const signalFor = (n) => (n > 0 ? AbortSignal.timeout(n) : undefined);
