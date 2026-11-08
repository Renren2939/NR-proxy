import express from "express";
import * as cheerio from "cheerio";
import dns from "node:dns/promises";
import net from "node:net";

const app = express();
const PORT = process.env.PORT || 3000;
const P = "/proxy?url=";
const TIMEOUT_MS = 15000;

app.disable("x-powered-by");
app.use((req, res, next) => {
  res.set("x-robots-tag", "noindex, nofollow"); // 検索エンジンにインデックスさせない
  next();
});
// 注意: アクセスログ(morganなど)は意図的に入れていません。個人情報を記録しないためです。

// ---------- SSRF対策: 内部ネットワークへのアクセスを禁止 ----------
function isPrivateIp(ip) {
  if (ip.startsWith("::ffff:")) ip = ip.slice(7);
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  const l = ip.toLowerCase();
  return l === "::1" || l === "::" || l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80");
}

// 環境変数 BLOCKED_DOMAINS="example.com,example.org" で利用不可のドメインを指定できます
const BLOCKED = (process.env.BLOCKED_DOMAINS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const isBlocked = (h) => BLOCKED.some((d) => h === d || h.endsWith("." + d));

async function assertPublic(u) {
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("http/httpsのみ対応しています");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (isBlocked(host.toLowerCase())) throw new Error("このサイトは利用できません");
  const ips = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true })).map((r) => r.address);
  if (!ips.length || ips.some(isPrivateIp)) throw new Error("このアドレスにはアクセスできません");
}

// ---------- URL書き換え ----------
function proxyUrl(raw, base) {
  if (!raw) return raw;
  const t = raw.trim();
  if (/^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i.test(t)) return raw;
  try {
    return P + encodeURIComponent(new URL(t, base).href);
  } catch {
    return raw;
  }
}

const rewriteSrcset = (v, base) =>
  v.split(",").map((part) => {
    const [u, ...rest] = part.trim().split(/\s+/);
    return [proxyUrl(u, base), ...rest].join(" ");
  }).join(", ");

const rewriteCss = (css, base) =>
  css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (_, __, u) => `url("${proxyUrl(u, base)}")`)
    .replace(/@import\s+(['"])(.*?)\1/gi, (_, __, u) => `@import "${proxyUrl(u, base)}"`);

// ページ内のfetch/XHR/GETフォームをプロキシ経由にするスクリプト
const clientScript = (base) => `<script>(function(){
var B=${JSON.stringify(base).replace(/</g, "\\u003c")},P="${P}";
function px(u){try{var a=new URL(u,B);if(a.protocol!=="http:"&&a.protocol!=="https:")return u;
if(a.origin===location.origin&&a.pathname==="/proxy")return u;return P+encodeURIComponent(a.href)}catch(e){return u}}
var f=window.fetch;window.fetch=function(i,o){
if(typeof i==="string"||i instanceof URL)i=px(String(i));else if(i instanceof Request)i=new Request(px(i.url),i);
return f.call(this,i,o)};
var x=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){arguments[1]=px(String(u));return x.apply(this,arguments)};
document.addEventListener("submit",function(e){var fm=e.target;if((fm.method||"get").toLowerCase()!=="get")return;
e.preventDefault();var a=new URL(fm.getAttribute("action")||B,B);
new URLSearchParams(new FormData(fm)).forEach(function(v,k){a.searchParams.set(k,v)});
location.href=P+encodeURIComponent(a.href)},true);
})();</script>`;

function rewriteHtml(html, base) {
  const $ = cheerio.load(html);

  // <base>タグがあれば基準URLに反映して削除
  const baseHref = $("base[href]").attr("href");
  if (baseHref) {
    try { base = new URL(baseHref, base).href; } catch {}
  }
  $("base").remove();

  // 整合性チェック・nonceは書き換えると壊れるので除去
  $("[integrity]").removeAttr("integrity");
  $("[nonce]").removeAttr("nonce");

  for (const attr of ["href", "src", "poster", "data-src"]) {
    $(`[${attr}]`).each((_, el) => {
      $(el).attr(attr, proxyUrl($(el).attr(attr), base));
    });
  }
  $("[srcset]").each((_, el) => $(el).attr("srcset", rewriteSrcset($(el).attr("srcset"), base)));
  $("[style]").each((_, el) => $(el).attr("style", rewriteCss($(el).attr("style"), base)));
  $("style").each((_, el) => $(el).text(rewriteCss($(el).text(), base)));

  // POSTフォームのみサーバー側で書き換え(GETフォームはクライアントスクリプトが処理)
  $("form").each((_, el) => {
    if (($(el).attr("method") || "get").toLowerCase() === "post") {
      $(el).attr("action", proxyUrl($(el).attr("action") || base, base));
    }
  });

  // <meta http-equiv="refresh" content="0; url=...">
  $('meta[http-equiv="refresh" i]').each((_, el) => {
    const c = $(el).attr("content") || "";
    $(el).attr("content", c.replace(/(url\s*=\s*)(.+)$/i, (_, a, u) => a + proxyUrl(u.replace(/['"]/g, ""), base)));
  });

  $("head").prepend(clientScript(base));
  return $.html();
}

// ---------- ルーティング ----------
app.get("/", (req, res) => {
  res.type("html").send(`<!doctype html><html lang="ja"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Web Proxy</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:15vh auto;padding:0 1rem}
form{display:flex;gap:.5rem}input{flex:1;padding:.6rem;font-size:1rem}button{padding:.6rem 1rem;font-size:1rem}</style>
<h1>Web Proxy</h1>
<form action="${P.split("?")[0]}" method="get">
<input name="url" placeholder="https://example.com" required autofocus>
<button>開く</button></form>
<ul style="color:#555;font-size:.9rem;margin-top:2rem;line-height:1.7">
<li>このサービスはアクセス内容やCookieを保存・記録しません。</li>
<li>通信はこのサーバーを経由します。パスワードや個人情報、決済情報は入力しないでください。</li>
<li>違法な目的や、利用先サイトの規約に反する目的では使用しないでください。</li>
</ul></html>`);
});

app.all("/proxy", express.raw({ type: () => true, limit: "10mb" }), async (req, res) => {
  try {
    let target = String(req.query.url || "").trim();
    if (!target) return res.status(400).send("urlパラメータが必要です");
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) target = "https://" + target;

    const url = new URL(target);
    await assertPublic(url);

    const headers = {
      "user-agent": req.get("user-agent") || "Mozilla/5.0",
      accept: req.get("accept") || "*/*",
      "accept-language": req.get("accept-language") || "en",
    };
    const hasBody = !["GET", "HEAD"].includes(req.method) && Buffer.isBuffer(req.body) && req.body.length;
    if (hasBody && req.get("content-type")) headers["content-type"] = req.get("content-type");

    const upstream = await fetch(url, {
      method: req.method,
      headers,
      body: hasBody ? req.body : undefined,
      redirect: "manual", // リダイレクト先も毎回検証するため自動追従しない
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });

    // リダイレクトはプロキシ経由のURLに変換して返す
    if (upstream.status >= 300 && upstream.status < 400 && upstream.headers.get("location")) {
      return res.redirect(upstream.status, proxyUrl(upstream.headers.get("location"), url.href));
    }

    const type = upstream.headers.get("content-type") || "application/octet-stream";
    const buf = Buffer.from(await upstream.arrayBuffer());

    res.status(upstream.status);
    res.set("content-type", type);
    res.set("cache-control", upstream.headers.get("cache-control") || "no-store");
    res.set("access-control-allow-origin", "*");
    // content-security-policy / x-frame-options / set-cookie などは意図的に転送しない

    if (/text\/html|application\/xhtml/i.test(type)) {
      const charset = (type.match(/charset=([^;]+)/i) || [])[1] || "utf-8";
      let html;
      try { html = new TextDecoder(charset.trim()).decode(buf); }
      catch { html = buf.toString("utf8"); }
      res.set("content-type", "text/html; charset=utf-8");
      return res.send(rewriteHtml(html, upstream.url || url.href));
    }
    if (/text\/css/i.test(type)) {
      return res.send(rewriteCss(buf.toString("utf8"), url.href));
    }
    res.send(buf);
  } catch (err) {
    res.status(502).type("text/plain; charset=utf-8").send("取得に失敗しました: " + err.message);
  }
});

app.listen(PORT, () => console.log(`Web proxy listening on :${PORT}`));
