// passwap token metadata + picker. No keys, no server.
//   const tokens = passwapTokens(web3, conn)
//   await tokens.resolve(mint)          -> { mint, symbol, name, logo, decimals, verified, program, source }
//   await tokens.holdings(owner)        -> [{ mint, amount (bigint), decimals, program }]
//   await tokens.search(text)           -> [meta...]   (a pasted mint, common tokens, then Jupiter's public search)
//   tokens.label(meta)                  -> "USDC · EPjF…t1v"
//   tokens.attachPicker(input, { onPick, holdings })  -> a dropdown under a text input
// Sources, in order: Jupiter's public token API (symbol, name, logo, verified), Token-2022 on-chain metadata,
// Metaplex metadata for classic mints, and finally the mint's decimals alone.
(function (root) {
  root.passwapTokens = function (web3, conn) {
    const { PublicKey } = web3;
    const JUP = "https://lite-api.jup.ag/tokens/v2/search?query=";
    const METAPLEX = new PublicKey("metaqbxxUufS4Zk9mMv2r2xMQ7XCpD3sNJcyfbYPHvj");
    const TOKEN = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"), TOKEN22 = new PublicKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
    const COMMON = [
      { mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", symbol: "USDC", name: "USD Coin" },
      { mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", symbol: "USDT", name: "Tether USD" },
      { mint: "So11111111111111111111111111111111111111112", symbol: "SOL", name: "Wrapped SOL" },
      { mint: "XkeTXo1125vz5H9svJpGiw4JvLbN8VmMu9cmMvspump", symbol: "DREGG", name: "Dragon's Egg" },
    ];
    const cache = new Map(), resolved = new Map();
    const short = (m) => `${m.slice(0, 4)}…${m.slice(-4)}`;
    // logos: a GitHub "blob" page is HTML, not an image; point at the raw file instead
    const logoUrl = (u) => { if (!u) return null; const m = String(u).match(/^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/blob\/([^?]+)/); return m ? `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}` : String(u).split("?")[0] + (String(u).includes("?") && !/github/.test(u) ? "?" + String(u).split("?")[1] : ""); };
    const isMint = (s) => { try { new PublicKey(s); return s.length >= 32; } catch { return false; } };
    let store = {}; try { store = JSON.parse(localStorage.getItem("passwap.tokens") || "{}"); } catch {}
    const remember = (m) => { try { store[m.mint] = { symbol: m.symbol, name: m.name, logo: m.logo, decimals: m.decimals, verified: m.verified, program: m.program }; localStorage.setItem("passwap.tokens", JSON.stringify(store)); } catch {} };

    async function jup(query) {
      try { const r = await fetch(JUP + encodeURIComponent(query), { mode: "cors" }); if (!r.ok) return []; const d = await r.json(); return (Array.isArray(d) ? d : d.tokens || []).map((t) => ({ mint: t.id, symbol: t.symbol, name: t.name, logo: logoUrl(t.icon), decimals: t.decimals, verified: !!t.isVerified, program: t.tokenProgram, source: "jupiter" })); } catch { return []; }
    }
    // Token-2022 metadata extension, then Metaplex, via one parsed account read each
    async function onchain(mint) {
      const pk = new PublicKey(mint);
      const info = await conn.getParsedAccountInfo(pk);
      if (!info.value) return null;
      const p = info.value.data && info.value.data.parsed && info.value.data.parsed.info;
      const meta = { mint, symbol: short(mint), name: "", logo: null, decimals: p ? p.decimals : 0, verified: false, program: info.value.owner.toBase58(), source: "chain" };
      const ext = p && (p.extensions || []).find((e) => e.extension === "tokenMetadata");
      if (ext && ext.state) { meta.symbol = ext.state.symbol || meta.symbol; meta.name = ext.state.name || ""; meta.uri = ext.state.uri; }
      else {
        const [pda] = PublicKey.findProgramAddressSync([new TextEncoder().encode("metadata"), METAPLEX.toBytes(), pk.toBytes()], METAPLEX);
        const md = await conn.getAccountInfo(pda);
        if (md) { const d = md.data; const str = (o) => { const n = new DataView(d.buffer, d.byteOffset).getUint32(o, true); return new TextDecoder().decode(d.slice(o + 4, o + 4 + n)).replace(/\0+$/, "").trim(); }; try { meta.name = str(65); meta.symbol = str(65 + 4 + 32) || meta.symbol; meta.uri = str(65 + 4 + 32 + 4 + 10); } catch {} }
      }
      if (!meta.logo && meta.uri) { try { const j = await (await fetch(meta.uri, { mode: "cors" })).json(); meta.logo = logoUrl(j.image); } catch {} }
      return meta;
    }
    async function resolve(mint) {
      if (cache.has(mint)) return cache.get(mint);
      const p = (async () => {
        const [j] = await jup(mint);
        let meta = j && j.mint === mint ? j : null;
        if (!meta) { try { meta = await onchain(mint); } catch {} }
        if (!meta && store[mint]) meta = { mint, ...store[mint], source: "cache" };
        if (!meta) meta = { mint, symbol: short(mint), name: "", logo: null, decimals: 0, verified: false, program: null, source: "none" };
        remember(meta); resolved.set(mint, meta); return meta;
      })();
      cache.set(mint, p); return p;
    }
    async function holdings(owner) {
      const out = [];
      for (const program of [TOKEN, TOKEN22]) {
        try {
          const r = await conn.getParsedTokenAccountsByOwner(owner, { programId: program });
          for (const a of r.value) { const i = a.account.data.parsed.info; const amt = BigInt(i.tokenAmount.amount); if (amt > 0n) out.push({ mint: i.mint, amount: amt, decimals: i.tokenAmount.decimals, program: program.toBase58() }); }
        } catch {}
      }
      return out;
    }
    async function search(text) {
      const t = text.trim(); if (!t) return [];
      if (isMint(t)) return [await resolve(t)];
      const q = t.toLowerCase();
      const common = COMMON.filter((c) => c.symbol.toLowerCase().startsWith(q) || c.name.toLowerCase().includes(q)).map((c) => resolve(c.mint));
      const [c, j] = await Promise.all([Promise.all(common), jup(t)]);
      const seen = new Set(); const out = [];
      for (const m of [...c, ...j]) if (!seen.has(m.mint)) { seen.add(m.mint); out.push(m); }
      return out.slice(0, 12);
    }
    const label = (m) => `${m.symbol} · ${short(m.mint)}`;
    const fmt = (amount, dec) => { const s = BigInt(amount).toString().padStart(dec + 1, "0"); return (s.slice(0, -dec) + "." + s.slice(-dec)).replace(/\.?0+$/, "") || "0"; };
    const row = (m, extra = "") => `<div class="tok" data-mint="${m.mint}">${m.logo ? `<img src="${m.logo}" alt="" onerror="this.remove()">` : `<span class="tok-blank"></span>`}<b>${escapeHtml(m.symbol)}</b><span class="tok-name">${escapeHtml(m.name || "")}</span><span class="tok-mint">${short(m.mint)}</span>${m.verified ? '<span class="tok-ok">✓</span>' : ""}${extra}</div>`;
    const escapeHtml = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

    // a dropdown under `input`: what the wallet holds, common tokens, then search results as you type
    function attachPicker(input, { onPick, holdings: getHoldings }) {
      const box = document.createElement("div"); box.className = "tok-box"; box.hidden = true; input.insertAdjacentElement("afterend", box);
      let seq = 0, held = null;
      const render = (groups) => {
        box.innerHTML = groups.filter((g) => g.items.length).map((g) => `<div class="tok-head">${g.title}</div>${g.items.map((it) => row(it.meta, it.extra)).join("")}`).join("") || `<div class="tok-head">nothing found. paste a mint address.</div>`;
        box.hidden = false;
        box.querySelectorAll(".tok").forEach((el) => { el.onmousedown = (e) => { e.preventDefault(); pick(el.dataset.mint); }; });
      };
      const pick = async (mint) => { const m = await resolve(mint); input.value = label(m); input.dataset.mint = mint; box.hidden = true; onPick(m); };
      const show = async () => {
        const my = ++seq; const text = input.value.trim();
        if (input.dataset.mint && text === label(await resolve(input.dataset.mint))) { /* a chosen token, untouched */ }
        const groups = [];
        if (!text || text === input.dataset.label) {
          if (getHoldings && held === null) { held = []; try { held = await getHoldings(); } catch {} }
          if (held && held.length) { const metas = await Promise.all(held.map((h) => resolve(h.mint))); groups.push({ title: "in your wallet", items: held.map((h, i) => ({ meta: metas[i], extra: `<span class="tok-bal">${fmt(h.amount, h.decimals)}</span>` })) }); }
          groups.push({ title: "common", items: (await Promise.all(COMMON.map((c) => resolve(c.mint)))).map((meta) => ({ meta })) });
        } else {
          groups.push({ title: "search", items: (await search(text)).map((meta) => ({ meta })) });
        }
        if (my === seq) render(groups);
      };
      input.addEventListener("focus", () => { input.dataset.label = input.value; show(); });
      input.addEventListener("input", () => { delete input.dataset.mint; show(); });
      input.addEventListener("blur", () => { setTimeout(() => { box.hidden = true; }, 150); });
      return { set: pick, refreshHoldings: () => { held = null; } };
    }
    const cached = (mint) => resolved.get(mint) || null;
    const sym = (mint) => { const m = resolved.get(mint); return m ? m.symbol : short(mint); };
    return { resolve, cached, sym, holdings, search, label, fmt, attachPicker, COMMON };
  };
})(typeof self !== "undefined" ? self : this);
