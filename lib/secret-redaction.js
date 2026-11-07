/** Strip operator secrets from model-facing and API summaries. */

const SECRET_ENV_KEY = /(?:^|_)(?:FOFA_KEY|API_KEY|API_SECRET|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)(?:_|$)|(?:^|_)KEY$/i;

export function isSecretEnvKey(key) {
  return SECRET_ENV_KEY.test(String(key || ""));
}

/** Keep a proxy usable as a host hint. Never return username or password. */
export function redactProxyUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try {
    const url = new URL(raw);
    if (url.username || url.password) {
      url.username = "";
      url.password = "";
      return url.href;
    }
    return raw;
  } catch {
    return "(configured)";
  }
}

export function redactEnv(env) {
  const out = {};
  const configured = {};
  for (const [key, value] of Object.entries(env || {})) {
    if (isSecretEnvKey(key)) {
      configured[key] = String(value || "").trim() !== "";
      out[key] = "";
    } else {
      out[key] = value;
    }
  }
  return { env: out, configured };
}

export function mergeEnvKeepingSecrets(previous, patch) {
  const prev = previous && typeof previous === "object" ? previous : {};
  const next = Object.assign({}, prev);
  if (!patch || typeof patch !== "object") return next;
  for (const [key, value] of Object.entries(patch)) {
    if (typeof value !== "string") continue;
    if (isSecretEnvKey(key) && value.trim() === "") continue;
    next[key] = value;
  }
  return next;
}
