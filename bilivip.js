/***************************************
 * BiliBili 会员模块 —— 单文件版
 *
 * 仓库内不含任何隐私参数：账号凭据与设备指纹都在运行时写入 $persistentStore。
 * 需要人工配置的项全部由 Loon 插件配置页填写（见 BiliBili.Vip.plugin 的 #!input / #!select）。
 *
 * 三种角色由运行环境自动判断：
 *   1) http-request  → 采集设备指纹 / 换鉴权头
 *   2) http-response → 捕获会员账号凭据（仅限指定 UID）
 *   3) cron          → 用 refresh_token 续期
 ***************************************/

const STORE_CRED = 'bili_vip_cred';
const STORE_FP = 'bili_vip_fp';

/* ================= 基础工具 ================= */

const B64C = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64dec(s) {
  s = String(s).replace(/[-_]/g, (m) => (m === '-' ? '+' : '/')).replace(/[^A-Za-z0-9+/=]/g, '');
  const out = []; let buf = 0, bits = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=') break;
    const v = B64C.indexOf(s[i]); if (v < 0) continue;
    buf = (buf << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
  }
  return out;
}
function b64enc(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
    const n = (a << 16) | ((b || 0) << 8) | (c || 0);
    out += B64C[(n >> 18) & 63] + B64C[(n >> 12) & 63];
    out += i + 1 < bytes.length ? B64C[(n >> 6) & 63] : '=';
    out += i + 2 < bytes.length ? B64C[n & 63] : '=';
  }
  return out;
}

function readVarint(buf, i) { let v = 0, shift = 0, b; do { b = buf[i++]; v += (b & 0x7f) * Math.pow(2, shift); shift += 7; } while (b & 0x80); return [v, i]; }
function writeVarint(v) { const out = []; while (v > 127) { out.push((v & 0x7f) | 0x80); v = Math.floor(v / 128); } out.push(v); return out; }
function pbParse(bytes) {
  const fields = []; let i = 0;
  while (i < bytes.length) {
    let key; [key, i] = readVarint(bytes, i);
    const field = Math.floor(key / 8), wire = key & 7;
    if (wire === 0) { let v; [v, i] = readVarint(bytes, i); fields.push({ field, wire, varint: v }); }
    else if (wire === 2) { let len; [len, i] = readVarint(bytes, i); fields.push({ field, wire, bytes: bytes.slice(i, i + len) }); i += len; }
    else if (wire === 5) { fields.push({ field, wire, fixed: bytes.slice(i, i + 4) }); i += 4; }
    else if (wire === 1) { fields.push({ field, wire, fixed: bytes.slice(i, i + 8) }); i += 8; }
    else throw new Error('pb wire=' + wire);
  }
  return fields;
}
function pbBuild(fields) {
  const out = [];
  for (const f of fields) {
    out.push(...writeVarint(f.field * 8 + f.wire));
    if (f.wire === 0) out.push(...writeVarint(f.varint));
    else if (f.wire === 2) { out.push(...writeVarint(f.bytes.length)); out.push(...f.bytes); }
    else out.push(...f.fixed);
  }
  return out;
}
/** 用模板结构替换指定字段（metadata-bin 中的 access_key / buvid） */
function pbPatch(templateB64, patch) {
  const fields = pbParse(b64dec(templateB64));
  const toBytes = (s) => { const a = []; for (let i = 0; i < s.length; i++) a.push(s.charCodeAt(i) & 0xff); return a; };
  for (const f of fields) if (patch[f.field] !== undefined && f.wire === 2) f.bytes = toBytes(patch[f.field]);
  return b64enc(pbBuild(fields));
}

function md5(str) {
  const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
             4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const K = []; for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296) | 0;
  const bytes = [];
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c < 0x80) bytes.push(c);
    else if (c < 0x800) bytes.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) bytes.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else bytes.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  const bitLen = bytes.length * 8;
  bytes.push(0x80); while (bytes.length % 64 !== 56) bytes.push(0);
  const lo = bitLen >>> 0, hi = Math.floor(bitLen / 4294967296) >>> 0;
  for (let i = 0; i < 4; i++) bytes.push((lo >>> (8 * i)) & 255);
  for (let i = 0; i < 4; i++) bytes.push((hi >>> (8 * i)) & 255);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const rotl = (n, s) => (n << s) | (n >>> (32 - s));
  const add = (a, b) => (a + b) | 0;
  for (let off = 0; off < bytes.length; off += 64) {
    const M = [];
    for (let i = 0; i < 16; i++) M[i] = bytes[off + i * 4] | (bytes[off + i * 4 + 1] << 8) | (bytes[off + i * 4 + 2] << 16) | (bytes[off + i * 4 + 3] << 24);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = add(add(add(F, A), K[i]), M[g]);
      A = D; D = C; C = B; B = add(B, rotl(F, S[i]));
    }
    a0 = add(a0, A); b0 = add(b0, B); c0 = add(c0, C); d0 = add(d0, D);
  }
  const hex = (x) => { let s = ''; for (let i = 0; i < 4; i++) s += ('0' + ((x >>> (8 * i)) & 255).toString(16)).slice(-2); return s; };
  return hex(a0) + hex(b0) + hex(c0) + hex(d0);
}

const enc = (v) => encodeURIComponent(v).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

/* ================= 配置与存储 ================= */

function cfg(key, def) {
  try { const v = $persistentStore.read(key); return v === null || v === undefined || v === '' ? def : v; } catch (e) { return def; }
}
function readJSON(key) {
  const raw = cfg(key, null);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}
function writeJSON(key, obj) { $persistentStore.write(JSON.stringify(obj), key); }

/** 静默模式：只推"失败 / 忽略"这类需要用户处理的消息 */
function silentMode() { return String(cfg('silent', '正常通知')).indexOf('静默') >= 0; }
function notify(title, sub, body, important) {
  if (silentMode() && !important) return;
  try { $notification.post(title, sub, String(body === undefined ? '' : body)); } catch (e) {}
}

/* ================= 角色 1a：采集设备指纹 ================= */

const FP_FIELDS = {
  'User-Agent': 'ua',
  'buvid': 'buvid',
  'x-bili-device-bin': 'deviceBin',
  'x-bili-fawkes-req-bin': 'fawkes',
  'x-bili-locale-bin': 'locale',
  'x-bili-network-bin': 'network',
  'x-bili-metadata-bin': 'metadataBin',
};

function headerLookup(h, name) {
  if (h[name] !== undefined && h[name] !== null) return h[name];
  const lower = name.toLowerCase();
  for (const k of Object.keys(h)) if (k.toLowerCase() === lower) return h[k];
  return undefined;
}

/**
 * 从真实 App 请求里采集设备指纹。
 * device-bin / buvid / fawkes / UA 是设备级信息，与登录哪个账号无关，可安全采集。
 * metadata-bin 仅作结构模板保存，其中的 access_key 在换头时会用会员账号的重建。
 */
function harvest(h, plat) {
  const fp = readJSON(STORE_FP) || {};
  const cur = fp[plat] || {};
  const next = Object.assign({}, cur);
  let touched = false;

  for (const header in FP_FIELDS) {
    const field = FP_FIELDS[header];
    const v = headerLookup(h, header);
    if (typeof v === 'string' && v.length > 8 && v !== cur[field]) {
      next[field] = v;
      touched = true;
    }
  }
  if (!touched) return cur;

  fp[plat] = next;
  writeJSON(STORE_FP, fp);
  if (!cur.deviceBin && next.deviceBin) {
    notify('B站会员', '设备指纹已采集', plat + ' · buvid ' + String(next.buvid || '').slice(0, 8) + '…');
  }
  return next;
}

/** 兼容旧版：凭据里手填过 ios/android 时迁移一次 */
function migrateLegacyFp(cred) {
  if (!cred || (!cred.ios && !cred.android)) return;
  const fp = readJSON(STORE_FP) || {};
  let touched = false;
  for (const plat of ['ios', 'android']) {
    if (cred[plat] && !fp[plat]) { fp[plat] = cred[plat]; touched = true; }
  }
  if (touched) writeJSON(STORE_FP, fp);
}

/* ================= 角色 1b：换鉴权头 ================= */

function isPlayerUrl(url) {
  const u = String(url || '');
  return /\/bilibili\.app\..*\/(PlayViewUnite|PlayURL|PlayView|Player)\b/.test(u) ||
         /\/x\/player\/(wbi\/)?playurl/.test(u);
}

function doRequest() {
  const h = ($request && $request.headers) || {};
  const ua = String(headerLookup(h, 'User-Agent') || '');
  const plat = /android/i.test(ua) ? 'android' : 'ios';

  // ① 任何 App 请求都先采集设备指纹（只读，不改请求）
  harvest(h, plat);

  // ② 非播放类接口原样放行（播放记录因此归属你自己的账号）
  if (!isPlayerUrl($request && $request.url)) return $done({});

  const cred = readJSON(STORE_CRED);
  if (!cred || !cred.accessKey) return $done({});

  migrateLegacyFp(cred);
  const fp = readJSON(STORE_FP) || {};
  const prof = fp[plat] || cred[plat];
  if (!prof || !prof.metadataBin) return $done({});

  h['Authorization'] = 'identify_v1 ' + cred.accessKey;
  h['Cookie'] = cred.cookie;
  if (prof.ua) h['User-Agent'] = prof.ua;
  if (prof.buvid) h['buvid'] = prof.buvid;
  if (prof.deviceBin) h['x-bili-device-bin'] = prof.deviceBin;
  if (prof.fawkes) h['x-bili-fawkes-req-bin'] = prof.fawkes;
  if (prof.locale) h['x-bili-locale-bin'] = prof.locale;
  if (prof.network) h['x-bili-network-bin'] = prof.network;

  // 身份模式
  const mode = String(cfg('keepMid', '覆盖为会员'));
  if (mode.indexOf('保持') < 0) h['x-bili-mid'] = String(cred.mid);

  // access_key 轮换后必须同步重建，否则与 Authorization 不一致
  h['x-bili-metadata-bin'] = pbPatch(prof.metadataBin, { 1: cred.accessKey, 6: prof.buvid || '' });

  const rnd = () => Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, '0');
  h['x-bili-trace-id'] = rnd() + rnd() + ':' + rnd() + rnd() + ':0:0';

  $done({ headers: h });
}

/* ================= 角色 2：捕获会员账号凭据 ================= */

function doCapture() {
  const body = $response && $response.body;
  if (!body) return $done({});

  let json; try { json = JSON.parse(body); } catch (e) { return $done({}); }
  const d = json && json.data;
  const ti = d && (d.token_info || d);
  if (!ti || !ti.access_token) return $done({});

  const mid = String(ti.mid || '');
  if (!mid) return $done({});

  // ① UID 白名单：插件里填的 targetMid 说了算
  const target = String(cfg('targetMid', '')).trim();
  if (target && mid !== target) {
    notify('B站会员', '已忽略', '捕获到 UID ' + mid + '（非目标 ' + target + '），未覆盖凭据', true);
    return $done({});
  }
  if (!target) {
    notify('B站会员', '提示', '未填写 targetMid，已锁定当前账号 ' + mid + '；若非会员账号请清除凭据后重试', true);
  }

  // ② 已锁定的凭据不会被其他账号覆盖
  const old = readJSON(STORE_CRED);
  if (old && old.mid && String(old.mid) !== mid) {
    notify('B站会员', '已忽略', '已有锁定账号 ' + old.mid + '，忽略 UID ' + mid, true);
    return $done({});
  }

  const cookies = (d.cookie_info && d.cookie_info.cookies) || [];
  let cookie = '';
  for (const c of cookies) cookie += (cookie ? '; ' : '') + c.name + '=' + c.value;
  if (/DedeUserID=/.test(cookie)) cookie = cookie.replace(/DedeUserID=[^;]*/, 'DedeUserID=' + mid);
  else cookie += (cookie ? '; ' : '') + 'DedeUserID=' + mid;

  writeJSON(STORE_CRED, {
    mid: mid,
    accessKey: ti.access_token,
    refreshToken: ti.refresh_token || '',
    cookie: cookie,
    updatedAt: Date.now(),
    expiresIn: ti.expires_in || 0,
  });

  const days = ti.expires_in ? (ti.expires_in / 86400).toFixed(0) : '?';
  notify('B站会员', '凭据已捕获', 'UID ' + mid + '，有效期约 ' + days + ' 天');
  $done({});
}

/* ================= 角色 3：自动续期 ================= */

// B 站客户端公开常量（所有第三方客户端通用，非隐私数据）
const APPS = {
  iphone: ['4ebafd7c4951b366', '8cb98205e9b2ad3669aad0fce12a4c13'],
  android: ['783bbb7264451d82', '2653583c8873dea268ab9386918b1d65'],
};

function doRefresh() {
  const cred = readJSON(STORE_CRED);
  if (!cred || !cred.refreshToken) return notify('B站会员', '续期跳过', '没有 refreshToken，需先抓一次登录', true);

  // 续期身份由插件配置决定：refresh_token 与登录时的 appkey 绑定，必须一致
  const platform = /android/i.test(String(cfg('platform', 'iPhone'))) ? 'android' : 'iphone';
  const pair = APPS[platform];
  const params = {
    appkey: pair[0],
    ts: String(Math.floor(Date.now() / 1000)),
    access_key: cred.accessKey,
    refresh_token: cred.refreshToken,
    mobi_app: platform,
    platform: platform === 'android' ? 'android' : 'ios',
  };
  const q = Object.keys(params).sort().map((k) => enc(k) + '=' + enc(params[k])).join('&');
  const form = q + '&sign=' + md5(q + pair[1]);

  $httpClient.post(
    {
      url: 'https://passport.bilibili.com/api/v2/oauth2/refresh_token',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    },
    function (err, resp, data) {
      if (err) return notify('B站会员', '续期失败', String(err).slice(0, 60), true);

      let json; try { json = JSON.parse(data); } catch (e) { return notify('B站会员', '续期失败', '返回非 JSON', true); }
      if (json.code !== 0) return notify('B站会员', '续期失败 code=' + json.code, json.message || '', true);

      const dd = json.data || {}; const ti = dd.token_info || {};
      const cookies = (dd.cookie_info && dd.cookie_info.cookies) || [];
      cred.accessKey = ti.access_token || cred.accessKey;
      cred.refreshToken = ti.refresh_token || cred.refreshToken;
      if (ti.mid) cred.mid = String(ti.mid);

      let cookie = cred.cookie || '';
      for (const c of cookies) {
        const re = new RegExp('(^|;\\s*)' + c.name + '=[^;]*');
        if (re.test(cookie)) cookie = cookie.replace(re, '$1' + c.name + '=' + c.value);
        else cookie += '; ' + c.name + '=' + c.value;
      }
      cookie = cookie.replace(/(^|;\s*)DedeUserID=[^;]*/, '$1DedeUserID=' + cred.mid);
      cred.cookie = cookie; cred.updatedAt = Date.now(); cred.expiresIn = ti.expires_in || 0;
      writeJSON(STORE_CRED, cred);

      notify('B站会员', '续期成功', '有效期约 ' + (ti.expires_in ? (ti.expires_in / 86400).toFixed(0) : '?') + ' 天');
    }
  );
}

/* ================= 入口 ================= */

(function main() {
  // 先判 $response：http-response 场景下 $request 通常也存在
  const hasResp = typeof $response !== 'undefined' && $response;
  const hasReq = typeof $request !== 'undefined' && $request;
  if (hasResp) return doCapture();
  if (hasReq) return doRequest();
  return doRefresh();
})();
