// The API of Surge, Loon and Quantumult X scripts, over the natives the core
// installs as `__native` (see script.rs).
(function (g) {
  const N = g.__native;
  delete g.__native;

  function bytes(b) {
    if (b === undefined || b === null || typeof b === 'string') return b;
    if (b instanceof ArrayBuffer) return new Uint8Array(b);
    if (ArrayBuffer.isView(b)) return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    if (typeof b === 'object') return JSON.stringify(b);
    return String(b);
  }
  function message(m) {
    if (!m || typeof m !== 'object') return m;
    const out = {};
    for (const k of Object.keys(m)) out[k] = m[k];
    if ('body' in out) out.body = bytes(out.body);
    if ('bodyBytes' in out) out.bodyBytes = bytes(out.bodyBytes);
    if (out.response && typeof out.response === 'object') out.response = message(out.response);
    return out;
  }
  g.$done = function (value) {
    N.done(value === undefined ? null : message(value));
  };

  function key(k) {
    return k === undefined || k === null ? '' : String(k);
  }
  g.$persistentStore = {
    read: (k) => N.read(key(k)) ?? null,
    write: (v, k) => N.write(v === undefined || v === null ? null : String(v), key(k)),
  };
  g.$prefs = {
    valueForKey: (k) => N.read(key(k)) ?? undefined,
    setValueForKey: (v, k) => N.write(String(v), key(k)),
    removeValueForKey: (k) => N.write(null, key(k)),
    removeAllValues: () => false,
  };

  function text(v) {
    if (typeof v === 'string') return v;
    if (v instanceof Error) return v.stack ? `${v.message}\n${v.stack}` : String(v);
    try {
      return JSON.stringify(v);
    } catch (_) {
      return String(v);
    }
  }
  const log = (...a) => N.log(a.map(text).join(' '));
  g.console = { log, info: log, warn: log, error: log, debug: log };
  g.$notification = {
    post: (title, subtitle, body) =>
      N.log('[notification] ' + [title, subtitle, body].filter((x) => x).join(' | ')),
  };
  g.$notify = g.$notification.post;

  g.atob = N.atob;
  g.btoa = N.btoa;
  if (typeof g.TextEncoder === 'undefined') {
    g.TextEncoder = class {
      get encoding() {
        return 'utf-8';
      }
      encode(s) {
        return N.utf8Encode(s === undefined ? '' : String(s));
      }
    };
  }
  if (typeof g.TextDecoder === 'undefined') {
    g.TextDecoder = class {
      get encoding() {
        return 'utf-8';
      }
      decode(b) {
        return b === undefined ? '' : N.utf8Decode(bytes(b));
      }
    };
  }

  const timers = [];
  let lastTimer = 0;
  g.setTimeout = function (f, ms, ...args) {
    const id = ++lastTimer;
    if (typeof f === 'function') timers.push({ id, at: N.now() + (Number(ms) || 0), f, args });
    return id;
  };
  // Intervals fire once: a script waiting on one must still end.
  g.setInterval = g.setTimeout;
  g.clearTimeout = g.clearInterval = function (id) {
    const i = timers.findIndex((t) => t.id === id);
    if (i >= 0) timers.splice(i, 1);
  };
  g.setImmediate = (f, ...args) => g.setTimeout(f, 0, ...args);

  const calls = [];
  let current = null;
  function request(method, options, callback) {
    if (typeof options === 'string') options = { url: options };
    options = options || {};
    const call = {
      kind: 'http',
      method: String(options.method || method).toUpperCase(),
      url: String(options.url || ''),
      headers: options.headers || {},
      body: bytes(options.body ?? null),
      timeout: Number(options.timeout) || 0,
      binary: !!(options['binary-mode'] || options.binaryMode),
      callback: typeof callback === 'function' ? callback : () => {},
    };
    calls.push(call);
  }
  g.$httpClient = {};
  for (const m of ['get', 'post', 'put', 'delete', 'head', 'options', 'patch']) {
    g.$httpClient[m] = (options, callback) => request(m, options, callback);
  }
  g.__next = function () {
    if (calls.length) {
      current = calls.shift();
      return current;
    }
    if (timers.length) {
      timers.sort((a, b) => a.at - b.at || a.id - b.id);
      return { kind: 'timer', at: timers[0].at };
    }
    return null;
  };
  g.__fire = function () {
    const t = timers.shift();
    if (t) t.f(...t.args);
  };
  g.__reply = function (error, status, headers, body) {
    const call = current;
    current = null;
    if (!call) return;
    if (error) call.callback(error, null, null);
    else call.callback(null, { status, statusCode: status, headers }, body);
  };

  g.$environment = { 'surge-version': '5.0.0', 'surge-build': '3000', language: 'zh-Hans', system: 'iOS' };
})(globalThis);
