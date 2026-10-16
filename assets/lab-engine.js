(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.P05Engine = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const PRODUCTS = Object.freeze([
    { id: "P-01", name: "kopi", price: 18000, active: true },
    { id: "P-02", name: "teh", price: 12000, active: true },
    { id: "P-03", name: "kakao", price: 25000, active: true },
    { id: "P-04", name: "arsip", price: 9000, active: false }
  ]);

  function tokenize(source) {
    const tokens = [];
    let i = 0;
    while (i < source.length) {
      const c = source[i];
      if (/\s/.test(c)) { i += 1; continue; }
      if (c === "-" && source[i + 1] === "-") break;
      if (c === "'") {
        let value = "";
        i += 1;
        let closed = false;
        while (i < source.length) {
          if (source[i] === "'" && source[i + 1] === "'") { value += "'"; i += 2; continue; }
          if (source[i] === "'") { closed = true; i += 1; break; }
          value += source[i++];
        }
        if (!closed) throw new SyntaxError("String literal tidak ditutup.");
        tokens.push({ type: "value", value });
        continue;
      }
      const two = source.slice(i, i + 2);
      if ([">=", "<=", "<>", "!="].includes(two)) { tokens.push({ type: "op", value: two }); i += 2; continue; }
      if (["=", ">", "<", "(", ")"].includes(c)) { tokens.push({ type: c === "(" || c === ")" ? c : "op", value: c }); i += 1; continue; }
      const number = source.slice(i).match(/^\d+(?:\.\d+)?/);
      if (number) { tokens.push({ type: "value", value: Number(number[0]) }); i += number[0].length; continue; }
      const word = source.slice(i).match(/^[A-Za-z_][A-Za-z0-9_]*/);
      if (word) {
        const raw = word[0];
        const upper = raw.toUpperCase();
        if (["AND", "OR"].includes(upper)) tokens.push({ type: upper, value: upper });
        else if (upper === "TRUE" || upper === "FALSE") tokens.push({ type: "value", value: upper === "TRUE" });
        else tokens.push({ type: "identifier", value: raw.toLowerCase() });
        i += raw.length;
        continue;
      }
      throw new SyntaxError(`Token tidak dikenal pada posisi ${i}.`);
    }
    tokens.push({ type: "EOF" });
    return tokens;
  }

  function compileWhere(source) {
    const tokens = tokenize(source);
    let cursor = 0;
    const peek = () => tokens[cursor];
    const take = type => {
      const token = peek();
      if (token.type !== type) throw new SyntaxError(`Diharapkan ${type}, ditemukan ${token.type}.`);
      cursor += 1;
      return token;
    };
    function operand(row) {
      const token = peek();
      if (token.type === "value") { cursor += 1; return token.value; }
      if (token.type === "identifier") { cursor += 1; return row[token.value]; }
      throw new SyntaxError("Operand tidak valid.");
    }
    function comparison(row) {
      if (peek().type === "(") { take("("); const value = expression(row); take(")"); return Boolean(value); }
      const left = operand(row);
      if (peek().type !== "op") return Boolean(left);
      const op = take("op").value;
      const right = operand(row);
      if (op === "=") return left === right;
      if (op === "<>" || op === "!=") return left !== right;
      if (op === ">") return left > right;
      if (op === "<") return left < right;
      if (op === ">=") return left >= right;
      if (op === "<=") return left <= right;
      return false;
    }
    function conjunction(row) {
      let value = comparison(row);
      while (peek().type === "AND") { take("AND"); const rhs = comparison(row); value = Boolean(value && rhs); }
      return value;
    }
    function expression(row) {
      let value = conjunction(row);
      while (peek().type === "OR") { take("OR"); const rhs = conjunction(row); value = Boolean(value || rhs); }
      return value;
    }
    return function evaluate(row) {
      cursor = 0;
      const result = expression(row);
      if (peek().type !== "EOF") throw new SyntaxError("Ekspresi memiliki token sisa.");
      return Boolean(result);
    };
  }

  function runInjectionVulnerable(input) {
    const query = `SELECT id,name,price FROM products WHERE name = '${String(input)}' AND active = true`;
    const where = query.slice(query.indexOf(" WHERE ") + 7);
    try {
      const evaluator = compileWhere(where);
      const rows = PRODUCTS.filter(row => evaluator(row));
      return { exploited: rows.length > 1, rows, query, evidence: `parser=executed; rowCount=${rows.length}`, error: "" };
    } catch (error) {
      return { exploited: false, rows: [], query, evidence: `parser=rejected; error=${error.message}`, error: error.message };
    }
  }

  function runInjectionSecure(input) {
    const value = String(input);
    const rows = PRODUCTS.filter(row => row.name === value && row.active === true);
    return { exploited: false, rows, query: "SELECT id,name,price FROM products WHERE name = ? AND active = true", parameters: [value], evidence: `parameterCount=1; rowCount=${rows.length}` };
  }

  const DOCUMENTS = Object.freeze([
    { id: "DOC-100", owner: "u-100", title: "Catatan Ayu", body: "Data sintetis A" },
    { id: "DOC-200", owner: "u-200", title: "Rencana Budi", body: "Data sintetis B" },
    { id: "DOC-300", owner: "u-300", title: "Anggaran Citra", body: "Data sintetis C" }
  ]);
  function accessResult(request, checkOwner) {
    const object = DOCUMENTS.find(item => item.id === String(request.objectId));
    const allowed = Boolean(object && (!checkOwner || object.owner === String(request.requester)));
    const data = allowed ? { ...object } : null;
    return { exploited: Boolean(data && data.owner !== String(request.requester)), status: allowed ? 200 : object ? 403 : 404, data, evidence: `lookup=${object ? "hit" : "miss"}; ownerCheck=${checkOwner}; returnedOwner=${data ? data.owner : "none"}; requester=${request.requester}` };
  }
  const runAccessVulnerable = request => accessResult(request || {}, false);
  const runAccessSecure = request => accessResult(request || {}, true);

  function executeDiagnostic(request, config) {
    const cases = { db: new Error("DB connection refused"), cache: new Error("Cache timeout") };
    const url = String(request || "");
    const kind = url.includes("case=cache") ? "cache" : "db";
    const error = cases[kind];
    const body = config.debug
      ? `500 ${error.message}\nstack=at diagnosticHandler (server.js:42)\nsecret=${config.diagnosticSecret}\nenvironment=${config.environment}`
      : "500 Internal Server Error\nreference=ERR-LOCAL-500";
    const exposed = body.includes(config.diagnosticSecret) && body.includes("stack=");
    return { exploited: exposed, status: 500, body, evidence: `debug=${config.debug}; secretExposed=${body.includes(config.diagnosticSecret)}; stackExposed=${body.includes("stack=")}` };
  }
  const runMisconfigVulnerable = request => executeDiagnostic(request, { debug: true, diagnosticSecret: "LAB_KEY_7f3", environment: "training" });
  const runMisconfigSecure = request => executeDiagnostic(request, { debug: false, diagnosticSecret: "LAB_KEY_7f3", environment: "training" });

  function b64url(value) {
    if (typeof Buffer !== "undefined") return Buffer.from(JSON.stringify(value)).toString("base64url");
    return btoa(unescape(encodeURIComponent(JSON.stringify(value)))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  }
  function decodePart(value) {
    try {
      if (typeof Buffer !== "undefined") return JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
      const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(decodeURIComponent(escape(atob(normalized))));
    } catch (_) { return null; }
  }
  function makeUnsignedToken(payload) { return `${b64url({ alg: "none", typ: "JWT" })}.${b64url(payload || { sub: "u-100" })}.`; }
  function verifyToken(token, legacy) {
    const parts = String(token || "").split(".");
    const header = parts.length === 3 ? decodePart(parts[0]) : null;
    const payload = parts.length === 3 ? decodePart(parts[1]) : null;
    if (!header || !payload) return { accepted: false, reason: "format token tidak valid", payload: null };
    if (legacy && header.alg === "none" && parts[2] === "") return { accepted: true, reason: "komponen lama menerima alg none", payload };
    if (header.alg !== "HS256" || parts[2] !== "LOCAL_VALID_SIGNATURE") return { accepted: false, reason: "algoritma atau signature ditolak", payload: null };
    return { accepted: true, reason: "signature HS256 valid", payload };
  }
  function runComponent(token, legacy) {
    const verification = verifyToken(token, legacy);
    return { exploited: Boolean(verification.accepted && verification.payload), accepted: verification.accepted, payload: verification.payload, evidence: `component=${legacy ? "token-kit@1.2.0" : "token-kit@2.4.1"}; accepted=${verification.accepted}; reason=${verification.reason}` };
  }
  const runComponentVulnerable = token => runComponent(token, true);
  const runComponentSecure = token => runComponent(token, false);

  return { PRODUCTS, DOCUMENTS, tokenize, compileWhere, runInjectionVulnerable, runInjectionSecure, runAccessVulnerable, runAccessSecure, executeDiagnostic, runMisconfigVulnerable, runMisconfigSecure, makeUnsignedToken, verifyToken, runComponentVulnerable, runComponentSecure };
});
