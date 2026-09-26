// passwap wallet adapter: one provider shape for the pages, from whatever wallets are present.
//   await passwapWallets.list(web3) -> [{ name, icon, connect(), publicKey, signTransaction(tx), signAllTransactions(txs) }]
// Sources: Wallet Standard wallets with a Solana chain (Talisman, Phantom, Solflare, Backpack, MetaMask, ...), discovered
// on every call so late-loading extensions are found; then legacy window injections not already claimed by a standard wallet.
(function (root) {
  const standard = [];
  const register = (...ws) => { for (const w of ws) if (w && w.chains && w.chains.some((c) => String(c).startsWith("solana:")) && w.features && w.features["standard:connect"] && w.features["solana:signTransaction"] && !standard.includes(w)) standard.push(w); };
  try { window.addEventListener("wallet-standard:register-wallet", (e) => { try { e.detail(register); } catch {} }); } catch {}
  const rescan = () => { try { window.dispatchEvent(new CustomEvent("wallet-standard:app-ready", { detail: { register } })); } catch {} };
  rescan();

  function wrapStandard(w, web3) {
    let account = null, chain = null;
    const ser = (tx) => tx.serialize({ requireAllSignatures: false, verifySignatures: false });
    const input = (tx) => ({ transaction: ser(tx), account, chain });
    const feat = () => w.features["solana:signTransaction"];
    return {
      name: w.name, icon: w.icon, kind: "standard", isConnected: false, publicKey: null,
      async connect() {
        const r = await w.features["standard:connect"].connect();
        const accounts = (r && r.accounts && r.accounts.length ? r.accounts : w.accounts) || [];
        account = accounts.find((a) => a.chains && a.chains.some((c) => String(c).startsWith("solana:"))) || accounts[0];
        if (!account) throw new Error(w.name + " connected but exposed no Solana account");
        chain = (account.chains || []).find((c) => c === "solana:mainnet") || (account.chains || []).find((c) => String(c).startsWith("solana:")) || "solana:mainnet";
        this.publicKey = new web3.PublicKey(account.publicKey); this.isConnected = true;
        return { publicKey: this.publicKey };
      },
      async signTransaction(tx) { const [out] = await feat().signTransaction(input(tx)); return web3.Transaction.from(out.signedTransaction); },
      async signAllTransactions(txs) { const outs = await feat().signTransaction(...txs.map(input)); return outs.map((o) => web3.Transaction.from(o.signedTransaction)); },
    };
  }
  function wrapLegacy(name, p) {
    return { name, icon: null, kind: "legacy", get isConnected() { return !!p.isConnected; }, get publicKey() { return p.publicKey; },
      async connect() { const r = await p.connect(); return { publicKey: r && r.publicKey ? r.publicKey : p.publicKey }; },
      signTransaction: (tx) => p.signTransaction(tx), signAllTransactions: (txs) => p.signAllTransactions ? p.signAllTransactions(txs) : Promise.all(txs.map((t) => p.signTransaction(t))) };
  }
  // legacy injections, by the global each wallet historically used
  const legacy = () => {
    const found = [];
    const add = (name, p) => { if (p && typeof p.connect === "function" && typeof p.signTransaction === "function" && !found.some((f) => f.p === p)) found.push({ name, p }); };
    try { add("Talisman", window.talismanSol); } catch {}
    try { add("Phantom", window.phantom && window.phantom.solana); } catch {}
    try { add("Solflare", window.solflare); } catch {}
    try { add("Backpack", window.backpack); } catch {}
    try { add("Glow", window.glow); } catch {}
    try { if (window.solana) add(window.solana.isPhantom ? "Phantom" : window.solana.isSolflare ? "Solflare" : window.solana.isTalisman ? "Talisman" : "window.solana", window.solana); } catch {}
    return found;
  };
  root.passwapWallets = {
    async list(web3) {
      rescan(); await new Promise((r) => setTimeout(r, 250)); rescan(); await new Promise((r) => setTimeout(r, 100));
      const out = standard.map((w) => wrapStandard(w, web3));
      const names = new Set(out.map((w) => w.name.toLowerCase()));
      for (const { name, p } of legacy()) if (!names.has(name.toLowerCase())) { out.push(wrapLegacy(name, p)); names.add(name.toLowerCase()); }
      return out;
    },
    // what the page can see, for a "why isn't my wallet listed" report
    debug() { return { standard: standard.map((w) => w.name), legacy: legacy().map((l) => l.name), globals: Object.keys(window).filter((k) => /sol|talisman|phantom|backpack|wallet/i.test(k)) }; },
  };
})(typeof self !== "undefined" ? self : this);
