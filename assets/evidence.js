(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.P05Evidence = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const STORAGE_KEY = "p05-ksi-owasp-state-v1";
  const MAX_IMAGES = 5;
  const MAX_SOURCE_BYTES = 12 * 1024 * 1024;
  const MAX_STORED_BYTES = 90 * 1024;
  const MAX_LONG_EDGE = 1280;
  const MAX_PIXELS = 16 * 1000 * 1000;
  const LIVE_FIELDS = ["vulnerableFilename", "secureFilename", "prediction", "payload", "beforeEvidence", "observation", "cause", "controlPatch", "afterEvidence", "comparison", "conclusion", "toolVersion"];
  const LAB_FIELDS = ["prediction", "input", "lockedPayload", "before", "observation", "cause", "control", "feedback", "patched", "after", "retestPayload", "comparison", "conclusion"];
  const RPS_LINES = [
    "CPMK-1: Menjelaskan prinsip keamanan informasi, kontrol akses, keamanan aplikasi, dan risiko LLM/AI seperti prompt injection.",
    "Sub-2: Menjelaskan identitas, autentikasi, otorisasi, least privilege, keamanan aplikasi, privasi, dan risiko LLM/AI.",
    "Indikator minggu 5: Menjelaskan risiko aplikasi web/API; minimal 60% kategori dipetakan benar.",
    "Materi: OWASP Top 10; injection; broken access control; security misconfiguration; vulnerable components.",
    "Metode: Case method; pemetaan risiko-kontrol; analisis bukti.",
    "Alokasi waktu: T: 1×50 menit; P: 1×170 menit; PT+KM: 2×60 menit",
    "Assessment: Latihan pemetaan OWASP", "Bobot: 5%", "Kode pustaka: PU-2",
    "Pustaka (verbatim): OWASP Foundation. OWASP Top 10. https://owasp.org/www-project-top-ten/",
    "Tahun: 2021", "Catatan pustaka: Kategori risiko aplikasi web dan kontrol mitigasi."
  ];

  function blankLive() { return Object.assign(Object.fromEntries(LIVE_FIELDS.map(key => [key, ""])), { images: [] }); }
  function blankLab() { return { prediction: "", input: "", lockedPayload: "", before: null, observation: "", cause: "", control: "", feedback: "", patched: false, after: null, retestPayload: "", comparison: "", conclusion: "" }; }
  function emptyState() {
    return {
      version: 1,
      identity: { nama: "", npm: "", kelas: "" },
      ethicalAccepted: false,
      labs: { "LAB-INJ": blankLab(), "LAB-BAC": blankLab(), "LAB-MIS": blankLab(), "LAB-COMP": blankLab() },
      mapping: { selections: {}, score: null },
      liveTasks: { "LIVE-1": blankLive(), "LIVE-2": blankLive(), "LIVE-3": blankLive(), "LIVE-4": blankLive() },
      lecturerNotes: ""
    };
  }
  function clone(value) { return JSON.parse(JSON.stringify(value)); }
  function cleanText(value) { return typeof value === "string" ? value : value == null ? "" : String(value); }
  function validImage(image) { return image && typeof image === "object" && /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/i.test(cleanText(image.data)); }
  function normalizeImages(images) { return (Array.isArray(images) ? images : []).filter(validImage).slice(0, MAX_IMAGES).map((image, i) => ({ id: cleanText(image.id) || `image-${i + 1}`, name: cleanText(image.name) || `bukti-${i + 1}.jpg`, data: image.data, sourceBytes: Number(image.sourceBytes) || 0, storedBytes: Number(image.storedBytes) || 0, width: Number(image.width) || 0, height: Number(image.height) || 0 })); }
  function normalizeState(raw) {
    const base = emptyState();
    const source = raw && typeof raw === "object" ? raw : {};
    ["nama", "npm", "kelas"].forEach(key => { base.identity[key] = cleanText(source.identity && source.identity[key]); });
    base.ethicalAccepted = source.ethicalAccepted === true;
    Object.keys(base.labs).forEach(id => {
      const incoming = source.labs && source.labs[id] && typeof source.labs[id] === "object" ? source.labs[id] : {};
      LAB_FIELDS.forEach(key => { if (["before", "after"].includes(key)) base.labs[id][key] = incoming[key] && typeof incoming[key] === "object" ? clone(incoming[key]) : null; else if (key === "patched") base.labs[id][key] = incoming[key] === true; else base.labs[id][key] = cleanText(incoming[key]); });
    });
    base.mapping.selections = source.mapping && source.mapping.selections && typeof source.mapping.selections === "object" ? Object.fromEntries(Object.entries(source.mapping.selections).map(([k, v]) => [cleanText(k), cleanText(v)])) : {};
    base.mapping.score = source.mapping && source.mapping.score && typeof source.mapping.score === "object" ? clone(source.mapping.score) : null;
    Object.keys(base.liveTasks).forEach(id => {
      const incoming = source.liveTasks && source.liveTasks[id] && typeof source.liveTasks[id] === "object" ? source.liveTasks[id] : {};
      LIVE_FIELDS.forEach(key => { base.liveTasks[id][key] = cleanText(incoming[key]); });
      base.liveTasks[id].images = normalizeImages(incoming.images);
    });
    base.lecturerNotes = cleanText(source.lecturerNotes);
    return base;
  }
  function safeLoad(storage) {
    try { const text = storage && typeof storage.getItem === "function" ? storage.getItem(STORAGE_KEY) : null; return text ? normalizeState(JSON.parse(text)) : emptyState(); }
    catch (_) { return emptyState(); }
  }
  function safeSave(storage, state) {
    try { if (!storage || typeof storage.setItem !== "function") return false; storage.setItem(STORAGE_KEY, JSON.stringify(normalizeState(state))); return true; }
    catch (_) { return false; }
  }
  function commitState(storage, current, mutate) {
    const previous = normalizeState(current);
    const candidate = clone(previous);
    mutate(candidate);
    const normalized = normalizeState(candidate);
    return safeSave(storage, normalized) ? { ok: true, state: normalized } : { ok: false, state: previous };
  }
  function resetAll(storage) { try { if (storage && typeof storage.removeItem === "function") storage.removeItem(STORAGE_KEY); } catch (_) {} return emptyState(); }
  function appendImages(current, incoming) { const safe = normalizeImages(current); const valid = normalizeImages(incoming); const room = Math.max(0, MAX_IMAGES - safe.length); return { images: safe.concat(valid.slice(0, room)), rejected: Math.max(0, (Array.isArray(incoming) ? incoming.length : 0) - room) }; }
  function removeImage(images, id) { return normalizeImages(images).filter(image => image.id !== id); }
  function bytesFromDataUrl(url) { const comma = url.indexOf(","); return comma < 0 ? 0 : Math.ceil((url.length - comma - 1) * 3 / 4); }
  function readFileAsDataURL(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result || ""));
      reader.onerror = () => reject(Error("Berkas gambar tidak dapat dibaca."));
      reader.readAsDataURL(file);
    });
  }
  async function compressFile(file) {
    if (!file || !/^image\//i.test(file.type || "")) throw Error("Pilih berkas gambar.");
    if (file.size > MAX_SOURCE_BYTES) throw Error("Sumber melebihi batas 12 MB.");
    const bitmap = await createImageBitmap(file);
    const originalWidth = Number(bitmap.width || 0);
    const originalHeight = Number(bitmap.height || 0);
    if (!originalWidth || !originalHeight) { bitmap.close(); throw Error("Dimensi gambar tidak valid."); }
    if (originalWidth * originalHeight > MAX_PIXELS) { bitmap.close(); throw Error("Dimensi gambar terlalu besar."); }

    const originalFits = Math.max(originalWidth, originalHeight) <= MAX_LONG_EDGE && file.size <= MAX_STORED_BYTES && /^image\/(?:jpeg|png|webp)$/i.test(file.type || "");
    const originalData = originalFits ? await readFileAsDataURL(file) : "";
    const initialScale = Math.min(1, MAX_LONG_EDGE / Math.max(originalWidth, originalHeight));
    let width = Math.max(1, Math.round(originalWidth * initialScale));
    let height = Math.max(1, Math.round(originalHeight * initialScale));
    const canvas = document.createElement("canvas");
    const context = canvas.getContext("2d", { alpha: false });
    if (!context) { bitmap.close(); throw Error("Canvas tidak tersedia untuk kompresi."); }

    let data = "";
    let bestBytes = Infinity;
    let bestWidth = width;
    let bestHeight = height;
    for (let scalePass = 0; scalePass < 7; scalePass += 1) {
      canvas.width = width;
      canvas.height = height;
      context.fillStyle = "#fff";
      context.fillRect(0, 0, width, height);
      context.drawImage(bitmap, 0, 0, width, height);
      for (let quality = 0.84; quality >= 0.28; quality -= 0.07) {
        const candidate = canvas.toDataURL("image/jpeg", Number(quality.toFixed(2)));
        const candidateBytes = bytesFromDataUrl(candidate);
        if (candidateBytes < bestBytes) {
          data = candidate;
          bestBytes = candidateBytes;
          bestWidth = width;
          bestHeight = height;
        }
        if (candidateBytes <= MAX_STORED_BYTES) break;
      }
      if (bestBytes <= MAX_STORED_BYTES) break;
      width = Math.max(1, Math.round(width * 0.82));
      height = Math.max(1, Math.round(height * 0.82));
    }
    bitmap.close();

    if (originalData && file.size <= bestBytes) {
      return { id: `img-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`, name: cleanText(file.name) || "bukti.jpg", data: originalData, sourceBytes: file.size, storedBytes: file.size, width: originalWidth, height: originalHeight };
    }
    if (bestBytes > MAX_STORED_BYTES) throw Error("Gambar tidak dapat dikompres ke target 90 KB.");
    return { id: `img-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`, name: cleanText(file.name) || "bukti.jpg", data, sourceBytes: file.size, storedBytes: bestBytes, width: bestWidth, height: bestHeight };
  }

  function esc(value) { return cleanText(value).replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char])); }
  function show(value) { const text = cleanText(value).trim(); return text ? esc(text) : "Belum diisi"; }
  function showObject(value) { return value && typeof value === "object" ? show(JSON.stringify(value, null, 2)) : "-"; }
  // Kolom yang diisi sistem saat lab dijalankan (bukan diketik mahasiswa) -> "Belum dijalankan" bila kosong.
  const SYSTEM_FIELDS = new Set(["lockedPayload", "before", "after", "retestPayload", "feedback"]);
  function started(record) { return Object.entries(record || {}).some(([key, v]) => !SYSTEM_FIELDS.has(key) && ((typeof v === "string" && v.trim() !== "") || (Array.isArray(v) && v.length > 0))); }
  function cell(record, key) { if (key === "before" || key === "after") return showObject(record[key]); return SYSTEM_FIELDS.has(key) && !cleanText(record[key]).trim() ? "Belum dijalankan" : show(record[key]); }
  function fieldRows(record, fields) { return fields.map(([key, label]) => `<tr><th>${esc(label)}</th><td>${cell(record, key)}</td></tr>`).join(""); }
  function imageThumbs(tasks) { return tasks.flatMap(task => normalizeImages(task.record.images).map(image => `<figure class="report-thumb"><img src="${image.data}" alt="Bukti ${esc(task.title)}: ${esc(image.name)}"><figcaption>${esc(task.title)} · ${esc(image.name)}</figcaption></figure>`)).join(""); }
  function imageAppendix(tasks) {
    const images = tasks.flatMap(task => normalizeImages(task.record.images).map(image => ({ task, image })));
    return images.map(({ task, image }, index) => `<figure class="report-full${index ? " page-break" : ""}"><img src="${image.data}" alt="Lampiran penuh ${esc(task.title)}: ${esc(image.name)}"><figcaption>${esc(task.title)} · ${esc(image.name)} · lampiran penuh</figcaption></figure>`).join("");
  }

  function renderReportHTML(state, context) {
    const safe = normalizeState(state);
    const labs = context && Array.isArray(context.labs) ? context.labs : [];
    const liveTasks = context && Array.isArray(context.liveTasks) ? context.liveTasks : [];
    const mappingCases = context && Array.isArray(context.mappingCases) ? context.mappingCases : [];
    // Tugas live: tampilkan tugas yang dikerjakan; bila belum ada sama sekali, tampilkan status tugas pilihan wajib.
    const live = liveTasks.map(task => ({ ...task, record: safe.liveTasks[task.id] || blankLive() }));
    const liveDone = live.filter(task => started(task.record));
    const labFields = [["prediction", "Prediksi"], ["input", "Payload/request mahasiswa"], ["lockedPayload", "Payload terkunci"], ["before", "Hasil rentan"], ["observation", "Observasi"], ["cause", "Sebab"], ["control", "Kontrol terpilih"], ["feedback", "Umpan balik kontrol"], ["after", "Hasil aman"], ["retestPayload", "Payload retest identik"], ["comparison", "Perbandingan"], ["conclusion", "Simpulan"]];
    const liveLabels = [["vulnerableFilename", "Nama file rentan"], ["secureFilename", "Nama file aman"], ["prediction", "Prediksi"], ["payload", "Payload/request"], ["beforeEvidence", "Bukti sebelum"], ["observation", "Observasi"], ["cause", "Sebab"], ["controlPatch", "Kontrol/deskripsi patch"], ["afterEvidence", "Bukti sesudah"], ["comparison", "Perbandingan"], ["conclusion", "Simpulan"], ["toolVersion", "Versi alat/browser"]];
    const score = safe.mapping.score || { correct: 0, total: mappingCases.length, percent: 0, passed: false };
    const printDate = new Date().toLocaleDateString("id-ID", { day: "2-digit", month: "long", year: "numeric" });
    return `<article class="official-report report-document report-body">
      <header class="report-letterhead letterhead"><img src="assets/logo-polinela.png" alt="Logo Politeknik Negeri Lampung"><div><p>POLITEKNIK NEGERI LAMPUNG</p><p>Program Studi D-III Manajemen Informatika</p><h1>LEMBAR HASIL PRAKTIKUM</h1><p>PMI_1522 Keamanan Sistem Informasi · semester 5 · pertemuan 5</p><p>P05 · OWASP Top 10 dan Risiko Aplikasi Web/API</p><p>Tanggal cetak: ${esc(printDate)}</p></div><img src="assets/logo-sdgs.jpg" alt="Logo Sustainable Development Goals"></header>
      <section><h2>Identitas dan Deklarasi Etis</h2><table><tr><th>Nama</th><td>${show(safe.identity.nama)}</td><th>NPM</th><td>${show(safe.identity.npm)}</td></tr><tr><th>Kelas</th><td>${show(safe.identity.kelas)}</td><th>Deklarasi Etis</th><td>${safe.ethicalAccepted ? "Disetujui" : "-"}</td></tr></table><p>Saya hanya menguji demonstrasi sintetis lokal dan berkas milik sendiri, tidak memasukkan data rahasia, serta menyajikan bukti tanpa rekayasa.</p></section>
      <section><h2>Kontrak RPS Pertemuan 5</h2>${RPS_LINES.map(line => `<p>${esc(line)}</p>`).join("")}</section>
      <section><h2>Pemetaan Aktivitas ke CPMK</h2><table><thead><tr><th>Aktivitas</th><th>Bukti</th><th>CPMK/Sub-CPMK</th></tr></thead><tbody><tr><td>Empat Lab Terpandu</td><td>Eksploit, patch, retest, refleksi</td><td>CPMK-1 / Sub-2</td></tr><tr><td>Pemetaan OWASP</td><td>Pilihan kategori dan skor ≥60%</td><td>CPMK-1 / Sub-2</td></tr><tr><td>Tugas Live (1 pilihan wajib, 2 pengayaan)</td><td>Dua HTML lokal, bukti sebelum-sesudah</td><td>CPMK-1 / Sub-2</td></tr></tbody></table></section>
      <section><h2>Lab Terpandu</h2>${labs.map(lab => `<section><h3>${esc(lab.title)}</h3><p><strong>Metode:</strong> ${esc(lab.method)}</p>${started(safe.labs[lab.id]) ? `<table>${fieldRows(safe.labs[lab.id], labFields)}</table>` : "<p><strong>Status:</strong> Lab belum dikerjakan (0 dari 7 tahap).</p>"}<details open><summary>Kode dan patch</summary><h4>Kode rentan</h4><pre>${esc(lab.vulnerableCode)}</pre><h4>Kode aman</h4><pre>${esc(lab.secureCode)}</pre><h4>Unified diff</h4><pre>${esc(lab.diff)}</pre></details></section>`).join("")}</section>
      <section><h2>Pemetaan OWASP</h2><p>Skor: ${score.correct || 0}/${score.total || mappingCases.length} (${score.percent || 0}%) · Ambang lulus 60% · ${score.passed ? "Lulus" : "Belum lulus"}</p><table><thead><tr><th>Kasus</th><th>Pilihan mahasiswa</th><th>Hasil</th></tr></thead><tbody>${mappingCases.map(item => { const selected = safe.mapping.selections[item.id]; return `<tr><td>${esc(item.id)} · ${esc(item.scenario)}</td><td>${show(selected)}</td><td>${selected ? selected === item.answer ? "Benar" : "Belum tepat" : "-"}</td></tr>`; }).join("")}</tbody></table></section>
      <section><h2>Tugas Live</h2>${liveDone.length ? "" : "<p><strong>Status:</strong> Belum ada tugas live yang dikerjakan (wajib memilih satu Tugas Live Pilihan).</p>"}${liveDone.map(task => `<section><h3>${esc(task.title)}</h3><p>${esc(task.specification)}</p><table>${fieldRows(task.record, liveLabels)}</table><h4>Thumbnail bukti</h4><div class="report-thumb-grid">${normalizeImages(task.record.images).length ? normalizeImages(task.record.images).map(image => `<figure class="report-thumb"><img src="${image.data}" alt="Bukti ${esc(task.title)}: ${esc(image.name)}"><figcaption>${esc(image.name)}</figcaption></figure>`).join("") : "<p>-</p>"}</div></section>`).join("")}</section>
      <section class="evidence-appendix"><h2>Lampiran Bukti Screenshot</h2>${imageAppendix(liveDone) || "<p>-</p>"}</section>
      <section><h2>Catatan dosen</h2><div class="notes-space">${show(safe.lecturerNotes)}</div></section>
      <section class="report-signatures signature-grid"><div><p>Bandar Lampung, ${esc(printDate)}</p><p>Tanda tangan mahasiswa</p><div class="signature-space"></div><p>${show(safe.identity.nama)}</p><p>NPM: ${show(safe.identity.npm)}</p></div><div><p>Tanda tangan dosen</p><div class="signature-space"></div><p><strong>Muhammad Reza Redo Islami. S.Kom.,M.T.I.</strong></p><p>Dosen Pengampu</p></div></section>
    </article>`;
  }
  return { STORAGE_KEY, MAX_IMAGES, MAX_SOURCE_BYTES, MAX_STORED_BYTES, MAX_LONG_EDGE, LIVE_FIELDS, LAB_FIELDS, RPS_LINES, emptyState, normalizeState, safeLoad, safeSave, commitState, resetAll, appendImages, removeImage, compressFile, renderReportHTML };
});
