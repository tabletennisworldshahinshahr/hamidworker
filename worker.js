// Build: 2024-11-20T12:00:00.000Z
// @ts-nocheck
var Z = Object.defineProperty;
var ee = (e, t, n) => t in e ? Z(e, t, { enumerable: !0, configurable: !0, writable: !0, value: n }) : e[t] = n;
var P = (e, t, n) => (ee(e, typeof t != "symbol" ? t + "" : t, n), n);
const te = {
  _VL_: atob("dmxlc3M="),
  _VL_CAP_: atob("VkxFU1M="),
  _VM_: atob("dm1lc3M="),
  _TR_: atob("dHJvamFu"),
  _TR_CAP_: atob("VHJvamFu"),
  _SS_: atob("c2hhZG93c29ja3M="),
  _V2_: atob("djJyYXk="),
  _project_: atob("SGFtaWRyZXph"),
  _website_: atob("aHR0cHM6Ly9iaWEtcGFpbi1iYWNoZS5naXRodWIuaW8vQlBCLVdvcmtlci1QYW5lbC8="),
  _public_proxy_ip_: atob("YnBiLnlvdXNlZi5pc2VnYXJvLmNvbQ==")
};
globalThis.dict = te;
globalThis.settings = {
  localDNS: "8.8.8.8",
  antiSanctionDNS: "178.22.122.100",
  fakeDNS: !1,
  enableIPv6: !0,
  allowLANConnection: !1,
  logLevel: "warning",
  remoteDNS: "https://8.8.8.8/dns-query",
  remoteDnsHost: {
    host: "8.8.8.8",
    isDomain: !1,
    ipv4: [],
    ipv6: []
  },
  proxyIPMode: "proxyip",
  proxyIPs: [],
  prefixes: [],
  outProxy: "",
  outProxyParams: {},
  cleanIPs: [],
  customCdnAddrs: [],
  customCdnHost: "",
  customCdnSni: "",
  bestVLTRInterval: 30,
  VLConfigs: !0,
  TRConfigs: !0,
  ports: [443],
  fingerprint: "chrome",
  enableTFO: !1,
  fragmentMode: "custom",
  fragmentLengthMin: 100,
  fragmentLengthMax: 200,
  fragmentIntervalMin: 1,
  fragmentIntervalMax: 1,
  fragmentMaxSplitMin: void 0,
  fragmentMaxSplitMax: void 0,
  fragmentPackets: "tlshello",
  bypassIran: !1,
  bypassChina: !1,
  bypassRussia: !1,
  bypassOpenAi: !1,
  bypassGoogleAi: !1,
  bypassMicrosoft: !1,
  bypassOracle: !1,
  bypassDocker: !1,
  bypassAdobe: !1,
  bypassEpicGames: !1,
  bypassIntel: !1,
  bypassAmd: !1,
  bypassNvidia: !1,
  bypassAsus: !1,
  bypassHp: !1,
  bypassLenovo: !1,
  blockAds: !1,
  blockPorn: !1,
  blockUDP443: !1,
  blockMalware: !1,
  blockPhishing: !1,
  blockCryptominers: !1,
  customBypassRules: [],
  customBlockRules: [],
  customBypassSanctionRules: [],
  warpRemoteDNS: "1.1.1.1",
  warpEndpoints: ["engage.cloudflareclient.com:2408"],
  bestWarpInterval: 30,
  xrayUdpNoises: [
    {
      type: "rand",
      packet: "50-100",
      delay: "1-1",
      applyTo: "ip",
      count: 5
    }
  ],
  knockerNoiseMode: "quic",
  noiseCountMin: 10,
  noiseCountMax: 15,
  noiseSizeMin: 5,
  noiseSizeMax: 10,
  noiseDelayMin: 1,
  noiseDelayMax: 1,
  amneziaNoiseCount: 5,
  amneziaNoiseSizeMin: 50,
  amneziaNoiseSizeMax: 100,
  panelVersion: "4.0.0"
};
function ne(e) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(e);
}
async function re(e, t) {
  const { httpConfig: { panelVersion: n }, settings: r } = globalThis;
  let s, o;
  try {
    if (s = await t.kv.get("proxySettings", "json"), o = await t.kv.get("warpAccounts", "json"), !s)
      await t.kv.put("proxySettings", JSON.stringify(r)), s = r;
    if (!o)
      o = await oe(t);
    if (n !== s.panelVersion)
      s = await se(e, t);
    return {
      settings: s,
      warpAccounts: o
    };
  } catch (i) {
    console.log(i);
    const l = i instanceof Error ? i.message : String(i);
    throw new Error(`An error occurred while getting KV: ${l}`);
  }
}
async function se(e, t) {
  const { settings: n, httpConfig: { panelVersion: r } } = globalThis, s = e.method === "PUT" ? await e.json() : null;
  let o;
  try {
    o = await t.kv.get("proxySettings", "json");
  } catch (c) {
    const d = c instanceof Error ? c.message : String(c);
    console.log(d);
    throw new Error(`An error occurred while getting current KV settings: ${d}`);
  }
  const i = async (c, d) => {
    var u;
    const f = (u = s == null ? void 0 : s[c]) != null ? u : (o == null ? void 0 : o[c]) != null ? o[c] : n[c];
    return d ? await d(f) : f;
  }, l = [
    ["remoteDNS"],
    ["remoteDnsHost", "remoteDNS", Pe],
    ["localDNS"],
    ["antiSanctionDNS"],
    ["enableIPv6"],
    ["fakeDNS"],
    ["logLevel"],
    ["allowLANConnection"],
    ["proxyIPMode"],
    ["proxyIPs"],
    ["prefixes"],
    ["outProxy"],
    ["outProxyParams", "outProxy", Ie],
    ["cleanIPs"],
    ["customCdnAddrs"],
    ["customCdnHost"],
    ["customCdnSni"],
    ["bestVLTRInterval"],
    ["VLConfigs"],
    ["TRConfigs"],
    ["ports"],
    ["fingerprint"],
    ["enableTFO"],
    ["fragmentMode"],
    ["fragmentLengthMin"],
    ["fragmentLengthMax"],
    ["fragmentIntervalMin"],
    ["fragmentIntervalMax"],
    ["fragmentMaxSplitMin"],
    ["fragmentMaxSplitMax"],
    ["fragmentPackets"],
    ["bypassIran"],
    ["bypassChina"],
    ["bypassRussia"],
    ["bypassOpenAi"],
    ["bypassGoogleAi"],
    ["bypassMicrosoft"],
    ["bypassOracle"],
    ["bypassDocker"],
    ["bypassAdobe"],
    ["bypassEpicGames"],
    ["bypassIntel"],
    ["bypassAmd"],
    ["bypassNvidia"],
    ["bypassAsus"],
    ["bypassHp"],
    ["bypassLenovo"],
    ["blockAds"],
    ["blockPorn"],
    ["blockUDP443"],
    ["blockMalware"],
    ["blockPhishing"],
    ["blockCryptominers"],
    ["customBypassRules"],
    ["customBlockRules"],
    ["customBypassSanctionRules"],
    ["warpRemoteDNS"],
    ["warpEndpoints"],
    ["bestWarpInterval"],
    ["xrayUdpNoises"],
    ["knockerNoiseMode"],
    ["noiseCountMin"],
    ["noiseCountMax"],
    ["noiseSizeMin"],
    ["noiseSizeMax"],
    ["noiseDelayMin"],
    ["noiseDelayMax"],
    ["amneziaNoiseCount"],
    ["amneziaNoiseSizeMin"],
    ["amneziaNoiseSizeMax"]
  ], a = await Promise.all(
    l.map(async ([c, d, u]) => [c, await i(d ?? c, u)])
  ), m = {
    ...Object.fromEntries(a),
    panelVersion: r
  };
  try {
    return await t.kv.put("proxySettings", JSON.stringify(m)), m;
  } catch (c) {
    const d = c instanceof Error ? c.message : String(c);
    console.log(c);
    throw new Error(`An error occurred while updating KV: ${d}`);
  }
}
async function Pe(e) {
  const { host: t, isHostDomain: n } = K(e), r = { host: t, isDomain: n, ipv4: [], ipv6: [] };
  if (n) {
    const { ipv4: s, ipv6: o } = await S(t);
    r.ipv4 = s, r.ipv6 = o;
  }
  return r;
}
function Ie(e) {
  if (!e)
    return {};
  const { _SS_: t, _TR_: n, _VL_: r, _VM_: s } = globalThis.dict;
  let o = new URL(e);
  const i = o.protocol.slice(0, -1), l = i === "ss" ? t : i.replace("socks5", "socks");
  if (l === s) {
    const m = JSON.parse(W(o.host));
    return {
      protocol: l,
      uuid: m.id,
      server: m.add,
      port: +m.port,
      aid: +m.aid,
      type: m.net,
      headerType: m.type,
      serviceName: m.path,
      authority: m.authority,
      path: m.path || void 0,
      host: m.host || void 0,
      security: m.tls,
      sni: m.sni,
      fp: m.fp,
      alpn: m.alpn || void 0
    };
  }
  const a = {
    protocol: l,
    server: o.hostname,
    port: +o.port
  };
  switch (l) {
    case r:
      return B(a, {
        uuid: o.username
      });
    case n:
      return B(a, {
        password: o.username
      });
    case t: {
      const c = W(o.username), [d, ...u] = c.split(":");
      return B(a, {
        method: d,
        password: u.join(":")
      });
    }
    case "socks":
    case "http": {
      let c, d;
      try {
        const u = W(o.username);
        u.includes(":") && ([c, d] = u.split(":"));
      } catch (u) {
        c = o.username, d = o.password;
      }
      return B(a, {
        user: c || void 0,
        pass: d || void 0
      }, !1);
    }
    default:
      return {};
  }
}
function ie(e, t) {
  const { pathname: n } = new URL(e.url), { UUID: r, TR_PASS: s, FALLBACK: o, DOH_URL: i } = t;
  globalThis.globalConfig = {
    userID: r,
    TrPass: s,
    pathName: decodeURIComponent(n),
    fallbackDomain: o || "speed.cloudflare.com",
    dohURL: i || "https://cloudflare-dns.com/dns-query"
  };
}
function le(e) {
  const { _public_proxy_ip_: t } = globalThis.dict;
  globalThis.wsConfig = {
    envProxyIPs: e.PROXY_IP,
    envPrefixes: e.PREFIX,
    defaultProxyIPs: [t],
    defaultPrefixes: [
      "[2a02:898:146:64::]",
      "[2602:fc59:b0:64::]",
      "[2602:fc59:11:64::]"
    ]
  };
}
function ae(e, t) {
  const { _VL_CAP_: n, _TR_CAP_: r, _website_: s } = globalThis.dict, { UUID: o, TR_PASS: i, SUB_PATH: l, kv: a } = t, { pathname: m, origin: c, searchParams: d, hostname: u } = new URL(e.url);
  if (!["/secrets", "/favicon.ico"].includes(decodeURIComponent(m))) {
    if (!o || !i)
      throw new Error(`Please set ${n} UUID and ${r} password first. Visit <a href="${c}/secrets" target="_blank">here</a> to generate them.`);
    if (!ne(o))
      throw new Error(`Invalid UUID: ${o}`);
    if (typeof a != "object")
      throw new Error(`KV Dataset is not properly set! Please refer to <a href="${s}" target="_blank">tutorials</a>.`);
  }
  globalThis.httpConfig = {
    panelVersion: "4.0.0",
    defaultHttpPorts: [80, 8080, 2052, 2082, 2086, 2095, 8880],
    defaultHttpsPorts: [443, 8443, 2053, 2083, 2087, 2096],
    hostName: u,
    client: decodeURIComponent(d.get("app") ?? ""),
    urlOrigin: c,
    subPath: l || o
  };
}
async function oe(e) {
  const t = [], n = "https://api.cloudflareclient.com/v0a4005/reg", r = [
    await E(),
    await E()
  ];
  for (const o of r) {
    const { config: i } = await async function(l) {
      try {
        return (await fetch(n, {
          method: "POST",
          headers: {
            "User-Agent": "insomnia/8.6.1",
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            install_id: "",
            fcm_token: "",
            tos: new Date().toISOString(),
            type: "Android",
            model: "PC",
            locale: "en_US",
            warp_enabled: !0,
            key: l.publicKey
          })
        })).json();
      } catch (a) {
        const m = a instanceof Error ? a.message : String(a);
        throw new Error(`Failed to get warp configs: ${m}`);
      }
    }(o);
    t.push({
      privateKey: o.privateKey,
      warpIPv6: `${i.interface.addresses.v6}/128`,
      reserved: i.client_id,
      publicKey: i.peers[0].public_key
    });
  }
  return await e.kv.put("warpAccounts", JSON.stringify(t)), t;
}
async function E() {
  const e = await crypto.subtle.generateKey(
    { name: "X25519", namedCurve: "X25519" },
    !0,
    ["deriveBits"]
  ), t = await crypto.subtle.exportKey("pkcs8", e.privateKey), n = new Uint8Array(t).slice(-32), r = new Uint8Array(
    await crypto.subtle.exportKey("raw", e.publicKey)
  ), s = (o) => btoa(String.fromCharCode(...o));
  return {
    publicKey: s(r),
    privateKey: s(n)
  };
}
function A(e) {
  return /^(?!-)(?:[A-Za-z0-9-]{1,63}.)+[A-Za-z]{2,}$/.test(e);
}
async function S(e, t = !1) {
  const { dohURL: n } = globalThis.globalConfig, r = `${n}?name=${encodeURIComponent(e)}`, s = {
    ipv4: `${r}&type=A`,
    ipv6: `${r}&type=AAAA`
  };
  try {
    const o = await ce(s.ipv4, 1), i = t ? [] : await ce(s.ipv6, 28);
    return { ipv4: o, ipv6: i };
  } catch (o) {
    const i = o instanceof Error ? o.message : String(o);
    throw new Error(`Error resolving DNS for ${e}: ${i}`);
  }
}
async function ce(e, t) {
  try {
    const r = await (await fetch(e, { headers: { accept: "application/dns-json" } })).json();
    return r.Answer ? r.Answer.filter((s) => s.type === t).map((s) => s.data) : [];
  } catch (r) {
    const s = r instanceof Error ? r.message : String(r);
    throw new Error(`Failed to fetch DNS records from ${e}: ${s}`);
  }
}
function K(e) {
  try {
    const n = new URL(e).hostname;
    return {
      host: n,
      isHostDomain: A(n)
    };
  } catch (t) {
    return {
      host: "",
      isHostDomain: !1
    };
  }
}
function W(e) {
  return new TextDecoder().decode(
    Uint8Array.from(atob(e), (t) => t.charCodeAt(0))
  );
}
Array.prototype.concatIf = function(e, t) {
  return e ? Array.isArray(t) ? [...this, ...t] : [...this, t] : this;
};
Object.prototype.omitEmpty = function() {
  if (Object.keys(this).length === 0)
    return;
  return this;
};
class he {
  constructor() {
    P(this, "alg", "HS256");
  }
  setProtectedHeader(t) {
    return this.p = t, this;
  }
  setIssuedAt(t) {
    return this.i = t, this;
  }
  setExpirationTime(t) {
    return this.e = t, this;
  }
  async sign(t) {
    var s;
    const n = { alg: this.alg, ...this.p };
    this.i === void 0 && (this.i = Math.floor(Date.now() / 1e3));
    const r = {
      ...this.c,
      iat: this.i
    };
    if (this.e !== void 0) {
      let o;
      if (typeof this.e == "number")
        o = this.i + this.e;
      else
        try {
          o = Date.parse(this.e) / 1e3;
        } catch {
          throw new TypeError(
            'Invalid "exp" claim timestamp value. To use a "TimeSpan" value, please input a numeric value'
          );
        }
      r.exp = o;
    }
    return [
      F(JSON.stringify(n)),
      F(JSON.stringify(r)),
      F(
        new Uint8Array(
          await crypto.subtle.sign(
            "HMAC",
            await crypto.subtle.importKey(
              "raw",
              t,
              { name: "HMAC", hash: "SHA-256" },
              !1,
              ["sign"]
            ),
            new TextEncoder().encode(
              `${F(JSON.stringify(n))}.${F(JSON.stringify(r))}`
            )
          )
        )
      )
    ].join(".");
  }
  constructor(t) {
    this.c = t;
  }
}
const de = (e) => new TextEncoder().encode(e), fe = (e) => new TextDecoder().decode(e), ue = (e) => {
  let t = "";
  for (const n of e)
    t += String.fromCharCode(n);
  return btoa(t).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
};
function F(e) {
  return ue(typeof e == "string" ? de(e) : e);
}
const ge = (e) => {
  let t = e;
  t.length % 4 == 2 && (t += "=="), t.length % 4 == 3 && (t += "="), t = t.replace(/-/g, "+").replace(/_/g, "/");
  const n = atob(t), r = new Uint8Array(n.length);
  for (let s = 0; s < n.length; s++)
    r[s] = n.charCodeAt(s);
  return r;
};
async function pe(e, t) {
  const n = e.split(".");
  if (n.length !== 3)
    throw new Error("Invalid Compact JWS");
  const r = ge(n[0]), s = ge(n[1]), o = fe(r), i = fe(s);
  if (!await async function(e, t, n, r) {
    return crypto.subtle.verify(
      "HMAC",
      await crypto.subtle.importKey(
        "raw",
        r,
        { name: "HMAC", hash: "SHA-256" },
        !1,
        ["verify"]
      ),
      n,
      de(`${e}.${t}`)
    );
  }(n[0], n[1], ge(n[2]), t))
    throw new Error("JWS Signature Verification Failed");
  return {
    payload: JSON.parse(i),
    protectedHeader: JSON.parse(o)
  };
}
async function me(e, t) {
  const n = e.method !== "POST" ? H(!1, 405, "Method not allowed.") : await e.text(), r = await t.kv.get("pwd");
  if (n !== r)
    return H(!1, 401, "Wrong password.");
  let s = await t.kv.get("secretKey");
  s || (s = function() {
    const l = new Uint8Array(32);
    return crypto.getRandomValues(l), Array.from(l, (a) => a.toString(16).padStart(2, "0")).join("");
  }(), await t.kv.put("secretKey", s));
  const o = new TextEncoder().encode(s), { userID: i } = globalThis.globalConfig;
  return H(!0, 200, "Successfully generated Auth token", null, {
    "Set-Cookie": `jwtToken=${await new he({ userID: i }).setProtectedHeader({ alg: "HS256" }).setIssuedAt().setExpirationTime("24h").sign(o)}; HttpOnly; Secure; Max-Age=604800; Path=/; SameSite=Strict`,
    "Content-Type": "text/plain"
  });
}
async function D(e, t) {
  var r;
  try {
    const s = await t.kv.get("secretKey");
    if (s === null)
      return console.log("Secret key not found in KV."), !1;
    const o = new TextEncoder().encode(s), i = (r = e.headers.get("Cookie")) == null ? void 0 : r.match(/(^|;\s*)jwtToken=([^;]*)/), l = i ? i[2] : null;
    if (!l)
      return console.log("Unauthorized: Token not available!"), !1;
    const { payload: a } = await pe(l, o);
    return console.log(`Successfully authenticated, User ID: ${a.userID}`), !0;
  } catch (s) {
    const o = s instanceof Error ? s.message : String(s);
    return console.log(o), !1;
  }
}
async function ve(e, t) {
  let n = await D(e, t);
  const r = await t.kv.get("pwd");
  if (r && !n)
    return H(!1, 401, "Unauthorized.");
  const s = await e.text();
  return s === r ? H(!1, 400, "Please enter a new Password.") : (await t.kv.put("pwd", s), H(!0, 200, "Successfully logged in!", null, {
    "Set-Cookie": "jwtToken=; Path=/; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "Content-Type": "text/plain"
  }));
}
function H(e, t, n, r, s) {
  const i = {
    "Content-Type": "application/json",
    ...s
  }, l = {
    success: e,
    status: t,
    message: n ?? null,
    body: r ?? null
  };
  return new Response(JSON.stringify(l), { status: t, headers: i });
}
function ye(e) {
  const { blockUDP443: t, enableIPv6: n } = globalThis.settings, r = [
    {
      ip_cidr: "172.19.0.2",
      action: "hijack-dns"
    },
    {
      clash_mode: "Direct",
      outbound: "direct"
    },
    {
      clash_mode: "Global",
      outbound: "\u2705 Selector"
    },
    {
      action: "sniff"
    },
    {
      protocol: "dns",
      action: "hijack-dns"
    },
    {
      ip_is_private: !0,
      outbound: "direct"
    }
  ];
  t && we(r, "reject", void 0, void 0, void 0, void 0, "udp", "quic", 443);
  const o = function() {
    const {
      localDNS: u,
      antiSanctionDNS: f,
      blockMalware: g,
      blockPhishing: b,
      blockCryptominers: h,
      blockAds: y,
      blockPorn: p,
      bypassIran: C,
      bypassChina: w,
      bypassRussia: N,
      bypassOpenAi: v,
      bypassGoogleAi: _,
      bypassMicrosoft: T,
      bypassOracle: R,
      bypassDocker: q,
      bypassAdobe: L,
      bypassEpicGames: O,
      bypassIntel: G,
      bypassAmd: I,
      bypassNvidia: x,
      bypassAsus: M,
      bypassHp: k,
      bypassLenovo: z
    } = globalThis.settings;
    return [
      { rule: g, type: "block", geosite: "geosite-malware", geoip: "geoip-malware", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs", geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-malware.srs" },
      { rule: b, type: "block", geosite: "geosite-phishing", geoip: "geoip-phishing", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs", geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-phishing.srs" },
      { rule: h, type: "block", geosite: "geosite-cryptominers", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs" },
      { rule: y, type: "block", geosite: "geosite-category-ads-all", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs" },
      { rule: p, type: "block", geosite: "geosite-nsfw", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-nsfw.srs" },
      { rule: C, type: "direct", dns: u, geosite: "geosite-ir", geoip: "geoip-ir", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs", geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs" },
      { rule: w, type: "direct", dns: u, geosite: "geosite-cn", geoip: "geoip-cn", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cn.srs", geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-cn.srs" },
      { rule: N, type: "direct", dns: u, geosite: "geosite-category-ru", geoip: "geoip-ru", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ru.srs", geoipURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ru.srs" },
      { rule: v, type: "direct", dns: f, geosite: "geosite-openai", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-openai.srs" },
      { rule: _, type: "direct", dns: f, geosite: "geosite-google-deepmind", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-google-deepmind.srs" },
      { rule: T, type: "direct", dns: f, geosite: "geosite-microsoft", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-microsoft.srs" },
      { rule: R, type: "direct", dns: f, geosite: "geosite-oracle", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-oracle.srs" },
      { rule: q, type: "direct", dns: f, geosite: "geosite-docker", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-docker.srs" },
      { rule: L, type: "direct", dns: f, geosite: "geosite-adobe", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-adobe.srs" },
      { rule: O, type: "direct", dns: f, geosite: "geosite-epicgames", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-epicgames.srs" },
      { rule: G, type: "direct", dns: f, geosite: "geosite-intel", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-intel.srs" },
      { rule: I, type: "direct", dns: f, geosite: "geosite-amd", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-amd.srs" },
      { rule: x, type: "direct", dns: f, geosite: "geosite-nvidia", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-nvidia.srs" },
      { rule: M, type: "direct", dns: f, geosite: "geosite-asus", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-asus.srs" },
      { rule: k, type: "direct", dns: f, geosite: "geosite-hp", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-hp.srs" },
      { rule: z, type: "direct", dns: f, geosite: "geosite-lenovo", geositeURL: "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-lenovo.srs" }
    ].filter(({ rule: u }) => u);
  }(), i = function(u) {
    const {
      customBypassRules: f,
      customBypassSanctionRules: g,
      customBlockRules: b
    } = globalThis.settings;
    return {
      bypass: {
        geosites: u.filter((h) => h.type === "direct").map((h) => h.geosite),
        geoips: u.filter((h) => h.type === "direct" && h.geoip).map((h) => h.geoip),
        domains: [
          ...f.filter(A),
          ...g.filter(A)
        ],
        ips: f.filter((h) => !A(h))
      },
      block: {
        geosites: u.filter((h) => h.type === "block").map((h) => h.geosite),
        geoips: u.filter((h) => h.type === "block" && h.geoip).map((h) => h.geoip),
        domains: b.filter(A),
        ips: b.filter((h) => !A(h))
      }
    };
  }(o);
  return {
    rules: r,
    rule_set: o.reduce((u, f) => (function(g, b) {
      const { geosite: h, geositeURL: y, geoip: p, geoipURL: C } = b, w = (N, v) => g.push({
        type: "remote",
        tag: N,
        format: "binary",
        url: v,
        download_detour: "direct"
      });
      h && y && w(h, y), p && C && w(p, C);
    }(u, f), u), []).omitEmpty(),
    auto_detect_interface: !0,
    default_domain_resolver: {
      server: "dns-direct",
      strategy: n ? "prefer_ipv4" : "ipv4_only",
      rewrite_ttl: 60
    },
    final: "\u2705 Selector"
  };
}
function we(e, t, n, r, s, o, i, l, a) {
  e.push({
    rule_set: s || o,
    domain_suffix: n != null && n.length ? n : void 0,
    ip_cidr: r != null && r.length ? r : void 0,
    network: i,
    protocol: l,
    port: a,
    action: t === "reject" ? "reject" : "route",
    outbound: t === "direct" ? "direct" : void 0
  });
}
function xe(e, t) {
  const n = t.reduce((r, s) => (function(o, i) {
    const { geosite: l, geoip: a, geositeURL: m, geoipURL: c, format: d } = i, u = d === "text" ? "txt" : d, f = (g, b, h) => {
      o[g] = {
        type: "http",
        format: d,
        behavior: b,
        path: `./ruleset/${g}.${u}`,
        interval: 86400,
        url: h
      };
    };
    l && m && f(l, "domain", m), a && c && f(a, "ipcidr", c);
  }(r, s), r), {}).omitEmpty();
  return [
    `GEOIP,lan,${e},no-resolve`,
    ...t.filter((r) => r.type === "block").flatMap((r) => [r.geosite ? `RULE-SET,${r.geosite},REJECT` : null, r.geoip ? `RULE-SET,${r.geoip},REJECT` : null]).filter(Boolean),
    ...t.filter((r) => r.type === "direct").flatMap((r) => [r.geosite ? `RULE-SET,${r.geosite},${e}` : null, r.geoip ? `RULE-SET,${r.geoip},${e}` : null]).filter(Boolean),
    `MATCH,${e}`
  ];
}
function Me() {
  const {
    localDNS: e,
    antiSanctionDNS: t,
    blockMalware: n,
    blockPhishing: r,
    blockCryptominers: s,
    blockAds: o,
    blockPorn: i,
    bypassIran: l,
    bypassChina: a,
    bypassRussia: m,
    bypassOpenAi: c,
    bypassGoogleAi: d,
    bypassMicrosoft: u,
    bypassOracle: f,
    bypassDocker: g,
    bypassAdobe: b,
    bypassEpicGames: h,
    bypassIntel: y,
    bypassAmd: p,
    bypassNvidia: C,
    bypassAsus: w,
    bypassHp: N,
    bypassLenovo: v
  } = globalThis.settings;
  return [
    { rule: o, type: "block", geosite: "geosite:category-ads-all" },
    { rule: o, type: "block", geosite: "geosite:category-ads-ir" },
    { rule: i, type: "block", geosite: "geosite:category-porn" },
    { rule: n, type: "block", geosite: "geosite:malware", geoip: "geoip:malware" },
    { rule: r, type: "block", geosite: "geosite:phishing", geoip: "geoip:phishing" },
    { rule: s, type: "block", geosite: "geosite:cryptominers" },
    { rule: l, type: "direct", geosite: "geosite:category-ir", geoip: "geoip:ir", dns: e },
    { rule: a, type: "direct", geosite: "geosite:cn", geoip: "geoip:cn", dns: e },
    { rule: m, type: "direct", geosite: "geosite:category-ru", geoip: "geoip:ru", dns: e },
    { rule: c, type: "direct", geosite: "geosite:openai", dns: t },
    { rule: d, type: "direct", geosite: "geosite:google-deepmind", dns: t },
    { rule: u, type: "direct", geosite: "geosite:microsoft", dns: t },
    { rule: f, type: "direct", geosite: "geosite:oracle", dns: t },
    { rule: g, type: "direct", geosite: "geosite:docker", dns: t },
    { rule: b, type: "direct", geosite: "geosite:adobe", dns: t },
    { rule: h, type: "direct", geosite: "geosite:epicgames", dns: t },
    { rule: y, type: "direct", geosite: "geosite:intel", dns: t },
    { rule: p, type: "direct", geosite: "geosite:amd", dns: t },
    { rule: C, type: "direct", geosite: "geosite:nvidia", dns: t },
    { rule: w, type: "direct", geosite: "geosite:asus", dns: t },
    { rule: N, type: "direct", geosite: "geosite:hp", dns: t },
    { rule: v, type: "direct", geosite: "geosite:lenovo", dns: t }
  ].filter(({ rule: _ }) => _);
}
var ke;
export default ke = {
  async fetch(e, t) {
    try {
      const n = e.headers.get("Upgrade");
      if (ie(e, t), n === "websocket")
        le(t);
      else {
        ae(e, t);
        const { pathName: s } = globalThis.globalConfig, o = s.split("/")[1];
        switch (o) {
          case "panel":
            return await async function(l, a) {
              const { pathName: m } = globalThis.globalConfig;
              switch (m) {
                case "/panel":
                  return await async function(c, d) {
                    if (await d.kv.get("pwd") && !await D(c, d)) {
                      const { urlOrigin: u } = globalThis.httpConfig;
                      return Response.redirect(`${u}/login`, 302);
                    }
                    return new Response(await Te("H4sIAAAAAAAAA1VTW3PbNhD+K1Y8x4J9ls24SUycbOPEzWlC46RjJ7YpERCSohESFAA0atXp33co+ZciB55JzGSPXezd3d19q+sLpI5k25hB6bT64hE01+iE1i5mC6U31EwKj09f/fXp35vB+l+2lIey/s/K8s/S2p5y7VlZWf+zsrwvJg2/kX5/eHh4eH/8eFm+O2rS98QxLp7R0Wz/x0N4+Hh4vL1++8F36O8Wn01Wf+bYn03+M/nJzBqT/+z8W+Y/s+yX+T973j85M3+20/f/Vf1fM/v5v5/68z+r/G/qH8x/5/687M5T5/n8MvB5T/L/vB/n//kP/8F/x/2T9eY/X8z+X82+f/d/l/rP8f+s5z/M/+3+l8z+v/X8Z/n/+b//A/pP2f8M/P/2/Xnz+V/P/mP1/mP//k/3/+M/M/mf/P+f75n/P/nL+z+z87n/T4fG5+jHq9P9Xq88/33/Dfrd6dfr6e4v6MvR371/X47l9f2z+Hw+F4+n+r/X/n37v0u/Pz7f7/V6PV8n3k9+/Xw93+/3e9/N5Xo9X0/1/+7+n8/lcr6f/V+v+r/a6/l+b3+e9+c9z+3/mvY/z+l+v3/+b8v+/H7+/r/f9/f+r+v/P+n/y/q/zP/9/B/P/+3+/v05/j//a72+/D//s/k/e/x/P8/z/Xz27/3/+/k/5n9M/vJ9/M/l/1+c/mf/l/k/9/t/v/y+c/v/m/+P9t+/r//3+v83/8f/q/V/nf9H+/wL+9+j39ffw///8X/b+n5/P9fT7+/v1/fV/lP+r/V/T/33eP1/35/3P7f/3f7+f/j/P/s//u+3v+3+3/3f7f9v/d/t/9/5v+//3fvX+e/y/2r/t+z/7v/9/P9u/+f8P3u/e//t/L+3/6f/3/7f/P+f/b//9/P+b/b//P+v+L+3/av/3/b/a/7/t/172/5j9f9z/Yv3P93+Y/V/q//7+7/f7fb/P3/P3+32/l8vlcrler1er+v9q/4/eLz/P5/N+v+/n6839P5f/x/1+v/29nv+3/c/pf/P/zP9N/5+39//+D8837e+eP6f6P2v98/l+3t8/+z/f+z/q37e/l8v6P5/+Wf6P3/vL8f7d+3/3P7P+T//P+/+j9v9j/Yv2P9n7f/t9/+P8//7fb/9vv7fL/f38P+b+n/l/v/3/7+X6/n+//mv7n9fP5fL3f/jfr/u/p/1/2/6j/Z+3/pv/n+v/n+X+/n/d/Vv9/6/5f/f+v9V9r/w/7/+r+n+//vP6/6v5f/V/d/2v/n+//f/+3/w/7P+/+/n+t//99/9c+/68079q+Wv97fD4/R6vB95e+f/v9Pv/H9v9+//+/T34/n/X4/Pz+m59P9a+3+/n+vl/P+3t9Pt9/7+ev6/V8P5/z8/69n8/n+/V+v29f/1/X8/N+v1/Px/x+v5/v93t/P6b3+36f/j/q/j/t/3t/z/n/rP7P3v/fP6b/qf/t/N//+f/L+/9q/w/7f+/9/+f5f+b/9/n/+33+3+3/y/t/mv+//+v/1/Wv2f/7fP6/2v/r9vf+//l8v7//f+/P+r+t+b/a/7P2vz/2f1/9/6+fv8v7//D+V93f9P/9/R/b//d+//b+//tf8X7b+0/yftf7n9L/+/y+fl+/f0f+79Lvy8+D+/8X14f7/z/4X2P+T/9f7P1f15j/k/zP9z/c/6f/9/5v9//d/p/2v9X9b+p/s/b/0/+r/V/T/6v/7/1/p/9n/R/Xv3P5P+j9v/d/1v/b+b+r/mv7P1L9p/av+7/p/1X+7+z/vft/+X73/t/Wv0f//x/+X7f5//x9v7//z/2f53+f//f7L+x/m/2/9j+d+r/vP+/v/d+Xz6fz/n6+fn//X7+/H6/nvfv8v9+/X++n+t/1f6/pv+Z+v8v/0frf7P9v9n/y/vP7D8/+j+n/y/p/5/+/9v/g/q/2v/n+//n/N+9v7f9L+j/9f6P639b/T/pP/n/y/qft/9/f3/eH++ff9/P/r/n/9X9f1D++8z/8b6f36f/v/r/V/f/av9/+b+9//7/b+t/2v7/9L8/9P/M/6X9L+r+v+t/l/b/aP/P+3/u/z/qf1b/r/V/Vf+f9n/V/Vf8v8/+//P/mP1f5//P+3/S/rP+X+//z/u/a/6v9b/X/R/Vv9b/K+2f6P9Z+991f8v/f63++f5/rX+r/f8v+f5/pf6f6P9N/c/sf1P7v+l/rft/+P+j+X/V/pft/2v+H9p/k/pP+P+l/jP+/+j/q/qf2f8n/l/ZftP5f63+7/d/Vv9f63+d/lf7f7/t/9n7f6v+//3/r/3/r/6v6X9f+/9v+r/i//f+//r/Wv2f9v+n+//R/tf7P2f6v9r+w/S/sP1/7f+z/X/l/W/r/qfsf0v7n9D/W/mf63+j/b/Uf3v/v/V/7f+7/r/0/9L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/S/r/8n6v+L+t/o/0X+b/h/u/wv5/+//F/a/sv5v5/0/0P9z+b+r+t+Z/Tf9//e/2v+H+//u/wf5v/b+//if8/9H+n/8/6397/R/w/1//X9v+t/Q/tf2n93/X/1f03+7+3/R/6f9v/D/x/xf0/9r/R/r/4v7//T/5/sv7L+j/m/3/0v+3+/+f/a/3P7f/L+//w/sf0v+P+5/0/1//z/v/mv1//L+t+2/Yf3P8r+1/Y/pf3v1L97+x/rf1X7n6//v/R/uP1/9D/e/t/2X/r/S/+f97+9/1/v/yftv8X9z/R/+/836f+b9r/t+5/z/2/0P9P9//X9j+R+7/T/v//v+L//+3/b/svyX+3/3/r/w/rf3f6H/T+t/3v97/d+7/sv7b+x/2/539r99/+/tf7v+//7/+/r/y/pft/7n+j/3/r/3/r/6v/n/N/x/qf3/6n/R/6ft/6H+3+7/l/R/5/2X9N/9/6v+r+p/b/b/tv0v6/+b/e/7f+D+7/8P8f+D+v/p/uf0/9n9/+l/5f5/7n+z9Z/+/0f9/+7/0/9L/p/zP+/+3/f/9f9P+//V/p/2P+//H+r/i/+v9L9Z/+/1/+L/+/p/s/9n+T/N/5P+f+//e/l/T/+/+X/P/0/y/9/+n/vfv/qP9/+f/y/u/8/5v/P+//pf+/v3/q/+//t/n/rf5P8//7/u/s/sv6/1/+/+v/b/tf2/8X+L/N/x/zf8/+//7f+//X9r+t+T/5f2f1/+L/l/R/x/3f+D9t/Wv0f/L/v/wfsP+P+3/X/pf+/8v9v+7/2/6/9T+l/p/qf2/+/9t+x/9/yv9b/B/u/+/8X/r/+/6f8/+n9f/R/y/+39j/+/x/t/0/6H+3/S/rf+P9n9D/b/b/yf1v+/9n+7/3/+/8/6/+T+9/lftv7//D+p/f/tf+/+t/k/u/8P8v+D+X/V/n/9v7X+//e/lf6/9/+z/x/qf8/43/j/pftf+P93/F/h/o/6/+T9f/Z/1v+D+//1/t/k/2P9b+//8f6v/n/f/zft//v+v97/P/2f+P+//b/w/vft/0v+f+p/i/tP+H/R/x/pP/H+h/c/sf2H9b/d/u/rX9P+9+z/u/2/8v6/8L/B/4f+P/L/h/q/0/7P8/639b/S/+/w/8f0/7X+//N/w/x/r/+/+X+x/w/zf8f8P8n/d/Vv9f63+d/j/2P83/X/L/q/y//n+L9+/i/cv+//3/3/1f+r/3/1P+39L/t/0/+b/N/j/xv+H+n+b/q/9H/t/p//X+//t/7P9n9L9//+/2f0P7H+//L/7/q/+/83/vftftf+//l/h/3P8n/l/W/pf8P+j/f/sf0P73/L/F/+/sP8P83/d/Z/vfv/4f6H+L+r/h/1v9T+h/pf6v8n9L/+/yP4383+//4//D+//8P9/9r/7/zfv/q/8/5v/v+t/u/+/+//s/xf6P+/+//ifpf2n8X/j/4/8P+/+r+d/R/+f6//T/l/4f0/+r+t/Q/sf7v9n/J/k/2v6n9z/D/+/z/9P9v+t/g/wfvf+P+D+9/Tf8/5/+//v/v/X//f8f9n+v/p/0v9L+f/t/4/9/+5/q/xf7n9f/u/r/pf/X+//1/9/+//d/+P6//v/x/r/6v6X+z9J/y/+n+3/l/ZftP5f5f7397/h/w/1//X9L+r+v+5/zP9/+9/j/w/3v/7/5f8v8X/H+//i/3f2//v/j/s/0/1n+t+t/sP+P8f8/6//1/p/2v9X9T+v/l/o/8v+/+//8X6/+b/t/6v/39v+//R/lf0f7X9D/Z/tf1/5X9z+1/+/3P+n/S/sv+//X/f/p/k/0/97+x/pfsf+X+7+v/k/0/w/7P+j+//Y/2f/D/N/y/1/9H+/+j/g/9v+v+//F/i/zf8f9P9P+//n/p/tf3f/r+//l/rf+X+x/n/qf6v7v+L+n+p/d/w/3v+H+r/8f8v97/t/1n/P+z/R/7f+/9X+//q/yf3v+n+//L+t+v/s/4v8n/x/t/sP9/9J/0/6n+P+//q/i/8P+v+//R/vftf3P7H+/+3/e/pf1P9H/+/4/2f8f5v+X+5/T/sv2f6X+v/R/y/pv7H/3/k/p/4X+H+n/V/y/t/3n+j/pf+X+j/B/o/y/0P+X+H+7/Y/2f/D/N/g/u/y/t/4P/L+//o/3v9H+/+q/R/+f6//T/pP/P+x/Y/8/5n/z/Z/p/23/D+//4P//f1f+7+//R/1v9T+h/+/uf/39b83fT+u+b/pftv2P/X/B/v/7v/f+//d/+P+//p/+f+//h//fv3+H/5v9v/B/S/r/8n6v+L+t/o/0X+b/h/u/wv5/+//F/a/sv5v5/0/0P9z+b+r+t+Z/Tf9//e/2v+H+//u/wf5v/b+//if8/9H+n/8/6397/R/w/1//X9v+t/Q/tf2n93/X/1f03+7+3/R/6f9v/D/x/xf0/9r/R/r/4v7//T/5/sv7L+j/m/3/0v+3+/+f/a/3P7f/L+//w/sf0v+P+5/0/1//z/v/mv1//L+t+2/Yf3P8r+1/Y/pf3v1L97+x/rf1X7n6//v/R/uP1/9D/e/t/2X/r/S/+f97+9/1/v/yftv8X9z/R/+/836f+b9r/t+5/z/2/0P9P9//X9j+R+7/T/v//v+L//+3/b/svyX+3/3/r/w/rf3f6H/T+t/3v97/d+7/sv7b+x/2/539r99/+/tf7v+//7/+/r/y/pft/7n+j/3/r/3/r/6v/n/N/x/qf3/6n/R/6ft/6H+3+7/l/R/5/2X9N/9/6v+r+p/b/b/tv0v6/+b/e/7f+D+7/8P8f+D+v/p/uf0/9n9/+l/5f5/7n+z9Z/+/0f9/+7/0/9L/p/zP+/+3/f/9f9P+//V/p/2P+//H+r/i/+v9L9Z/+/1/+L/+/p/s/9n+T/N/5P+f+//e/l/T/+/+X/P/0/y/9/+n/vfv/qP9/+f/y/u/8/5v/P+//pf+/v3/q/+//t/n/rf5P8//7/u/s/sv6/1/+/+v/b/tf2/8X+L/N/x/zf8/+//7f+//X9r+t+T/5f2f1/+L/l/R/x/3f+D9t/Wv0f/L/v/wfsP+P+3/X/pf+/8v9v+7/2/6/9T+l/p/qf2/+/9t+x/9/yv9b/B/u/+/8X/r/+/6f8/+n9f/R/y/+39j/+/x/t/0/6H+3/S/rf+P9n9D/b/b/yf1v+/9n+7/3/+/8/6/+T+9/lftv7//D+p/f/tf+/+t/k/u/8P8v+D+X/V/n/9v7X+//e/lf6/9/+z/x/qf8/43/j/pftf+P93/F/h/o/6/+T9f/Z/1v+D+//1/t/k/2P9b+//8f6v/n/f/zft//v+v97/P/2f+P+//b/w/vft/0v+f+p/i/tP+H/R/x/pP/H+h/c/sf2H9b/d/u/rX9P+9+z/u/2/8v6/8L/B/4f+P/L/h/q/0/7P8/639b/S/+/w/8f0/7X+//N/w/x/r/+/+X+x/w/zf8f8P8n/d/Vv9f63+d/j/2P83/X/L/q/y//n+L9+/i/cv+//3/3/1f+r/3/1P+39L/t/0/+b/N/j/xv+H+n+b/q/