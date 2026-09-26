// passwap wallet adapter: one provider shape for the pages, from whatever wallets are present.
//   passwapWallets.list(web3) -> [{ name, icon, connect(), publicKey, signTransaction(tx), signAllTransactions(txs) }]
// Sources, in order: Wallet Standard wallets with a Solana chain (Talisman, Phantom, Solflare, Backpack, ...),
// then a legacy window.solana injection if no standard wallet claimed it.
(function (root) {
  const standard = [];
  const register = (...ws) => { for (const w of ws) if (w && w.chains && w.chains.some((c) => String(c).startsWith("solana:")) && w.features && w.features["standard:connect"] && w.features["solana:signTransaction"] && !standard.includes(w)) standard.push(w); };
  try { window.addEventListener("wallet-standard:register-wallet", (e) => { try { e.detail(register); } catch {} }); } catch {}
  try { window.dispatchEvent(new CustomEvent("wallet-standard:app-ready", { detail: { register } })); } catch {}

  function wrapStandard(w, web3) {
    let account = null, chain = null;
    const ser = (tx) => tx.serialize({ requireAllSignatures: false, verifySignatures: false });
    const input = (tx) => ({ transaction: ser(tx), account, chain });
    const feat = () => w.features["solana:signTransaction"];
    return {
      name: w.name, icon: w.icon, isConnected: false, publicKey: null,
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
  function wrapLegacy(p) {
    return { name: p.isPhantom ? "Phantom" : p.isSolflare ? "Solflare" : "injected wallet", icon: null, get isConnected() { return !!p.isConnected; }, get publicKey() { return p.publicKey; },
      async connect() { const r = await p.connect(); return { publicKey: r && r.publicKey ? r.publicKey : p.publicKey }; },
      signTransaction: (tx) => p.signTransaction(tx), signAllTransactions: (txs) => p.signAllTransactions ? p.signAllTransactions(txs) : Promise.all(txs.map((t) => p.signTransaction(t))) };
  }
  root.passwapWallets = {
    list(web3) {
      const out = standard.map((w) => wrapStandard(w, web3));
      if (!out.length && window.solana) out.push(wrapLegacy(window.solana));
      return out;
    },
  };
})(typeof self !== "undefined" ? self : this);
