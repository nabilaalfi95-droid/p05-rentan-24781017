(function (root, factory) {
  const engine = typeof module === "object" && module.exports ? require("./lab-engine.js") : root.P05Engine;
  const api = factory(engine);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.P05Labs = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (E) {
  "use strict";

  function sevenSteps(subject, requestName, attackResult, controlName, retestResult) {
    return [
      { number: 1, title: "Prediksi", action: `Tulis prediksi tentang ${subject} sebelum menjalankan simulator.`, visibleResult: "Textarea tetap dapat diedit dan ringkasan prediksi tampil pada kartu lab.", checkpoint: "Prediksi menyebut hasil yang diharapkan serta alasan teknis awal.", troubleshooting: "Jika ragu, baca kembali mekanisme pada teori dan identifikasi batas kepercayaan.", evidence: "Simpan kalimat prediksi yang dapat dibandingkan dengan hasil eksekusi." },
      { number: 2, title: "Ketik request", action: `Ketik sendiri ${requestName}; kolom sengaja kosong dan contoh hanya ada sebagai placeholder.`, visibleResult: "Request aktual ditampilkan persis dari nilai yang diketik, tanpa dijalankan otomatis.", checkpoint: "Nilai bukan placeholder, tidak kosong, dan hanya memakai data sintetis lokal.", troubleshooting: "Jika tombol belum aktif, lengkapi prediksi dan setiap field request yang wajib.", evidence: "Catat request atau command aktual yang akan diberikan kepada implementasi rentan." },
      { number: 3, title: "Jalankan versi rentan", action: `Jalankan serangan terhadap implementasi rentan ${subject}.`, visibleResult: `${attackResult}; payload baru terkunci jika kondisi eksploit benar-benar tercapai.`, checkpoint: "Status eksploit berasal dari hasil fungsi yang dieksekusi, bukan pencocokan kata payload.", troubleshooting: "Jika belum tereksploitasi, baca bukti teknis, ubah input, lalu jalankan kembali secara lokal.", evidence: "Rekam request, response, keputusan mesin, dan bukti teknis sebelum patch." },
      { number: 4, title: "Observasi dan sebab", action: "Tulis observasi terhadap output kemudian jelaskan penyebab pada field terpisah.", visibleResult: "Dua textarea tetap dapat diedit walaupun tahapan tindakan lain masih terkunci.", checkpoint: "Observasi berisi fakta keluaran; sebab menghubungkan fakta dengan kelemahan kode.", troubleshooting: "Hindari hanya menulis berhasil; sebut nilai status, jumlah baris, pemilik, konfigurasi, atau verifier.", evidence: "Simpan observasi dan analisis sebab yang dapat diperiksa dari jejak eksekusi." },
      { number: 5, title: "Pilih kontrol", action: `Pilih satu dari sedikitnya tiga kontrol dan terapkan ${controlName}.`, visibleResult: "Pilihan salah memberi umpan balik kausal dan patch/retest tetap terkunci; pilihan benar menampilkan diff.", checkpoint: "Diff yang terlihat memuat kode dihapus bertanda minus dan kode ditambah bertanda plus.", troubleshooting: "Jika kontrol ditolak, baca alasan kegagalan dan pilih kontrol yang bekerja pada lapisan penyebab.", evidence: "Catat nama kontrol, alasan pemilihan, kode aman, dan unified diff yang aktif." },
      { number: 6, title: "Retest identik", action: "Jalankan ulang payload yang terkunci tanpa mengubah satu karakter pun.", visibleResult: `${retestResult}; bukti sesudah patch tampil bersebelahan dengan bukti sebelum.`, checkpoint: "Payload retest sama persis dengan locked payload dan implementasi aman aktif.", troubleshooting: "Jika tombol terkunci, pastikan eksploit awal sukses dan kontrol yang benar sudah dipilih.", evidence: "Simpan request identik, response aman, keputusan mesin, dan bukti teknis sesudah patch." },
      { number: 7, title: "Bandingkan dan simpulkan", action: "Tulis perbandingan sebelum-sesudah serta simpulan terpisah berbasis bukti.", visibleResult: "Tracker menandai tujuh tahap selesai setelah kedua textarea terisi.", checkpoint: "Simpulan menjawab apakah kontrol memutus mekanisme serangan tanpa mengubah payload.", troubleshooting: "Jika status belum selesai, lengkapi perbandingan dan simpulan; semua textarea tetap editable.", evidence: "Simpan perbandingan, simpulan, dan status akhir sebagai bukti belajar." }
    ];
  }

  const LABS = [
    {
      id: "LAB-INJ", caseId: "guided-catalog-filter", topic: "injection", title: "Lab 1 · Injection pada katalog minuman",
      method: "Mini tokenizer → parser ekspresi → evaluator per baris",
      purpose: "Membuktikan bahwa konkatenasi input mengubah struktur ekspresi WHERE, lalu membandingkannya dengan parameterisasi yang memperlakukan input sebagai data.",
      requestLabel: "Nilai parameter name", placeholder: "contoh bentuk uji: tutup string, buat kondisi benar, lalu komentar",
      vulnerableCode: "const where = `name = '${input}' AND active = true`;\nreturn products.filter(compileWhere(where));",
      secureCode: "const sql = '... WHERE name = ? AND active = true';\nreturn products.filter(p => p.name === input && p.active);",
      diff: "--- a/catalog-rentan.js\n+++ b/catalog-aman.js\n-const where = `name = '${input}' AND active = true`;\n-return products.filter(compileWhere(where));\n+const sql = 'SELECT ... WHERE name = ? AND active = true';\n+return products.filter(p => p.name === input && p.active);",
      controls: [
        { id: "escape-output", label: "Escape HTML pada hasil", feedback: "Gagal: encoding keluaran tidak mencegah input mengubah struktur ekspresi WHERE di lapisan data." },
        { id: "parameterized-query", label: "Parameterized query dan binding", feedback: "Berhasil: struktur query dipisahkan dari nilai sehingga seluruh payload diperlakukan sebagai satu data." },
        { id: "hide-errors", label: "Sembunyikan pesan error", feedback: "Gagal: pesan generik mengurangi informasi, tetapi evaluator masih menjalankan logika hasil konkatenasi." }
      ], correctControl: "parameterized-query",
      steps: sevenSteps("filter katalog", "payload parameter pencarian", "jumlah baris dan ekspresi WHERE tampil", "parameterized query", "payload menjadi nilai literal dan tidak mengembalikan seluruh katalog")
    },
    {
      id: "LAB-BAC", caseId: "guided-student-note", topic: "broken-access-control", title: "Lab 2 · Broken access control pada catatan mahasiswa",
      method: "Object lookup → ownership decision → response projection",
      purpose: "Menunjukkan bahwa object lookup yang berhasil belum berarti akses sah; keputusan harus memeriksa kepemilikan objek terhadap identitas sesi.",
      requestLabel: "requester dan objectId", placeholder: "u-100|DOC-200",
      vulnerableCode: "const doc = documents.find(d => d.id === objectId);\nreturn response(200, doc);",
      secureCode: "const doc = documents.find(d => d.id === objectId);\nif (!doc || doc.owner !== session.sub) return response(403);\nreturn response(200, doc);",
      diff: "--- a/note-rentan.js\n+++ b/note-aman.js\n const doc = documents.find(d => d.id === objectId);\n+if (!doc || doc.owner !== session.sub) return response(403);\n return response(200, doc);",
      controls: [
        { id: "random-id", label: "Buat ID lebih panjang", feedback: "Gagal: ID sulit ditebak bukan keputusan otorisasi; objek tetap kembali bila ID diketahui dari log atau tautan." },
        { id: "ownership-check", label: "Cek ownership di server", feedback: "Berhasil: objek hanya dikembalikan ketika owner cocok dengan subject pada sesi tepercaya." },
        { id: "hide-link", label: "Sembunyikan tautan dengan CSS", feedback: "Gagal: klien masih dapat mengirim request objek langsung dan server belum memeriksa kepemilikan." }
      ], correctControl: "ownership-check",
      steps: sevenSteps("akses objek", "requester|objectId", "lookup, owner objek, requester, dan status response tampil", "server-side ownership check", "objek pengguna lain ditolak dengan status 403")
    },
    {
      id: "LAB-MIS", caseId: "guided-health-error", topic: "security-misconfiguration", title: "Lab 3 · Security misconfiguration pada error diagnostik",
      method: "Error path execution → debug renderer → exposure inspection",
      purpose: "Mengeksekusi jalur error dengan konfigurasi debug dan memeriksa apakah response benar-benar memuat secret serta metadata stack.",
      requestLabel: "Path diagnostik", placeholder: "/diagnostic/fail?case=db",
      vulnerableCode: "const config = { debug: true, diagnosticSecret: secret };\nreturn debugError(error, config);",
      secureCode: "const config = { debug: false };\nlogInternal(error);\nreturn '500 Internal Server Error';",
      diff: "--- a/diagnostic-rentan.js\n+++ b/diagnostic-aman.js\n-const config = { debug: true, diagnosticSecret: secret };\n-return debugError(error, config);\n+const config = { debug: false };\n+logInternal(error);\n+return '500 Internal Server Error';",
      controls: [
        { id: "client-mask", label: "Tutupi teks dengan CSS", feedback: "Gagal: secret masih berada pada response mentah dan dapat dibaca tanpa tampilan CSS." },
        { id: "disable-debug", label: "Matikan debug dan sanitasi error", feedback: "Berhasil: jalur error publik hanya memuat pesan generik sementara detail dicatat internal." },
        { id: "rename-secret", label: "Ganti nama variabel secret", feedback: "Gagal: mengganti nama tidak mengubah debug renderer yang menyalin nilai konfigurasi ke response." }
      ], correctControl: "disable-debug",
      steps: sevenSteps("endpoint diagnostik", "path error sintetis", "body response, secretExposed, dan stackExposed tampil", "debug off dan error sanitization", "response generik tidak memuat secret atau stack")
    },
    {
      id: "LAB-COMP", caseId: "guided-token-library", topic: "vulnerable-components", title: "Lab 4 · Vulnerable component pada verifier token",
      method: "Token decode → dependency verifier decision → protected result",
      purpose: "Membandingkan perilaku dependency lama yang menerima token tanpa signature dengan versi tetap yang memerlukan algoritma dan signature tepercaya.",
      requestLabel: "Token sintetis", placeholder: "header.payload.signature — buat token alg none dari penjelasan tahap",
      vulnerableCode: "const result = tokenKitLegacy.verify(token, { allowUnsigned: true });\nreturn result.accepted;",
      secureCode: "const result = tokenKitFixed.verify(token, { algorithms: ['HS256'] });\nreturn result.accepted && result.signatureValid;",
      diff: "--- a/verifier-rentan.js\n+++ b/verifier-aman.js\n-const result = tokenKitLegacy.verify(token, { allowUnsigned: true });\n+const result = tokenKitFixed.verify(token, { algorithms: ['HS256'] });\n-return result.accepted;\n+return result.accepted && result.signatureValid;",
      controls: [
        { id: "longer-token", label: "Wajibkan token lebih panjang", feedback: "Gagal: panjang token tidak membuktikan integritas dan token unsigned masih dapat diperpanjang." },
        { id: "upgrade-pin", label: "Upgrade, pin versi, dan uji verifier", feedback: "Berhasil: implementasi tetap menolak alg none dan hanya menerima algoritma serta signature yang disetujui." },
        { id: "base64-twice", label: "Encode payload dua kali", feedback: "Gagal: encoding bukan signature; komponen rentan tetap memercayai token tanpa bukti integritas." }
      ], correctControl: "upgrade-pin",
      steps: sevenSteps("verifier dependency", "token unsigned sintetis", "versi komponen, keputusan accepted, dan payload hasil decode tampil", "upgrade dan pin dependency", "token sama ditolak karena algoritma atau signature")
    }
  ];

  const WORKED_EXAMPLES = [
    { id: "EX-1", caseId: "worked-order-sort", title: "Contoh kerja · parameter urut pesanan", steps: ["Data: sort=total_desc, tiga pesanan sintetis.", "Pisahkan nama kolom dari arah urut.", "Petakan pilihan ke allowlist kolom.", "Hasil: input tidak menjadi fragmen bebas."] },
    { id: "EX-2", caseId: "worked-team-calendar", title: "Contoh kerja · kalender tim", steps: ["Data: user u-17 meminta event EV-92 milik tim lain.", "Lookup menemukan objek tetapi policy menolak tenant berbeda.", "Bukti: 403 dan body kosong.", "Kontrol: tenant dan ownership pada server."] },
    { id: "EX-3", caseId: "worked-header-baseline", title: "Contoh kerja · header baseline", steps: ["Response sintetis kehilangan Content-Security-Policy.", "Bandingkan dengan baseline deployment.", "Tambahkan header pada konfigurasi pusat.", "Retest menunjukkan header terpasang."] },
    { id: "EX-4", caseId: "worked-image-parser", title: "Contoh kerja · inventaris parser gambar", steps: ["SBOM menunjukkan image-parser 3.1.", "Advisory lokal menandai versi di bawah 3.4.", "Upgrade pada cabang uji.", "Regression test file normal dan rusak lulus."] }
  ];

  function liveProcedure(subject, visible, check, fix) {
    return [
      { action: `Buat folder lokal kosong dan dua file untuk ${subject} memakai pola nama yang ditentukan.`, visibleResult: "Dua nama file dengan NPM dan nama kasus terlihat di File Explorer.", checkpoint: "Kedua file berekstensi .html dan tidak berada di folder unduhan sementara.", troubleshooting: "Aktifkan tampilan ekstensi file bila nama berakhir .html.txt.", proof: "Ambil screenshot File Explorer yang memperlihatkan kedua nama file." },
      { action: "Tulis kerangka HTML lokal sederhana dan data sintetis tanpa menyalin kode jawaban lengkap.", visibleResult: `${visible} muncul ketika file rentan dibuka melalui file://.`, checkpoint: "Halaman terbuka tanpa server dan Developer Tools tidak menunjukkan request jaringan.", troubleshooting: "Periksa penutup tag dan Console bila layar kosong.", proof: "Ambil screenshot halaman rentan dan alamat file:// pada browser." },
      { action: "Tambahkan implementasi rentan sendiri sesuai deskripsi mekanisme, lalu simpan.", visibleResult: "Form menerima request tetapi belum mengeksekusi sebelum tombol lokal dipilih.", checkpoint: "Kode hanya mengubah data sintetis pada halaman itu sendiri.", troubleshooting: "Tambahkan console output sementara untuk memeriksa alur fungsi, lalu hapus sebelum bukti akhir.", proof: "Ambil screenshot potongan kode rentan dan form yang siap diuji." },
      { action: "Ketik payload/request sendiri dan jalankan terhadap file rentan.", visibleResult: `${check} tampak sebagai hasil sebelum perbaikan.`, checkpoint: "Catat payload aktual dan bukti sebelum; jangan mengubah payload setelah ini.", troubleshooting: "Jika hasil berbeda, periksa data fixture dan jalur eksekusi, bukan mencari payload di string.", proof: "Ambil screenshot payload serta output sebelum pada satu bingkai bila mungkin." },
      { action: `Terapkan ${fix} pada file aman dan jelaskan patch dengan kata sendiri.`, visibleResult: "File aman tetap menjalankan fungsi normal tetapi memakai keputusan kontrol yang baru.", checkpoint: "Patch menyasar penyebab dan bukan sekadar menyembunyikan hasil di antarmuka.", troubleshooting: "Bandingkan fungsi rentan dan aman baris demi baris untuk menemukan batas kepercayaan.", proof: "Ambil screenshot potongan patch file aman tanpa menampilkan data pribadi." },
      { action: "Salin payload yang sama persis dan jalankan pada file aman.", visibleResult: "Hasil setelah perbaikan menolak eksploit sementara penggunaan normal tetap bekerja.", checkpoint: "Payload sebelum dan sesudah identik; hanya implementasinya yang berbeda.", troubleshooting: "Gunakan salin-tempel dari field bukti payload bila ada perbedaan karakter.", proof: "Ambil screenshot payload identik dan output sesudah perbaikan." },
      { action: "Isi observasi, sebab, kontrol, perbandingan, simpulan, versi browser, lalu unggah 1-5 screenshot.", visibleResult: "Kartu tugas menampilkan seluruh field serta thumbnail yang dapat dihapus satu per satu.", checkpoint: "Setiap screenshot relevan, terbaca, dan tidak memuat credential atau data nyata.", troubleshooting: "Jika gambar ditolak, pastikan sumber maksimal 12 MB dan gunakan format gambar yang didukung browser.", proof: "Ambil screenshot akhir kartu tugas; laporan akan mencetak thumbnail dan lampiran penuh." }
    ];
  }  const skeletonInjection = `<!DOCTYPE html>
<html>
<head><title>Pencarian Produk</title></head>
<body>
  <h2>Pencarian Produk (Rentan)</h2>
  <!-- Todo: Buat input pencarian dan tombol submit -->
  <div id="results">
    <!-- Hasil pencarian akan tampil di sini -->
  </div>
  <script>
    const products = [
      { id: 1, name: "Laptop", user: "admin", price: 1000 },
      { id: 2, name: "Mouse", user: "user", price: 50 }
    ];
    // Todo: Impelemntasi fungsi pencarian yang rentan input injection
  </script>
</body>
</html>`;

  const skeletonAccess = `<!DOCTYPE html>
<html>
<head><title>Dokumen Privat</title></head>
<body>
  <h2>Dokumen Privat</h2>
  <!-- Todo: Tampilkan detail dokumen sesuai ID yang diminta -->
  <script>
    const documents = [
      { id: "SEC-01", owner: "userA", content: "Rahasia A" },
      { id: "SEC-02", owner: "userB", content: "Rahasia B" }
    ];
    let currentUser = "userA"; 
    // Todo: Selesaikan fungsi menampilkan dokumen tanpa cek izin
  </script>
</body>
</html>`;

  const skeletonMisconfig = `<!DOCTYPE html>
<html>
<head><title>Endpoint Diagnostik</title></head>
<body>
  <h2>Error Diagnostik</h2>
  <button onclick="triggerError()">Uji Diagnostik</button>
  <pre id="output"></pre>
  <script>
    const CONFIG = { DEBUG: true, SECRET: "super_secret_key" };
    function triggerError() {
      // Todo: Lempar error dan tangkap. Render pesan, stack, dan config ke output
    }
  </script>
</body>
</html>`;

  const skeletonComponent = `<!DOCTYPE html>
<html>
<head><title>Dependency Upgrade</title></head>
<body>
  <h2>Cek Komponen Status</h2>
  <!-- Todo: Validasi signature dengan komponen versi lama -->
  <script>
    const OLD_VERIFIER_VER = "1.0.0";
    // Todo: Implementasi verifier sederhana menerima 'none' algorithm
  </script>
</body>
</html>`;

  const LIVE_TASKS = [
    { id: "LIVE-1", caseId: "live-product-search", title: "Tugas Live Pilihan: Pencarian produk (Injection)", vulnerableFilename: "{NPM}-product-search-rentan.html", secureFilename: "{NPM}-product-search-aman.html", specification: "Pilih SATU skenario sebagai tugas wajib. Bangun pencarian produk lokal dengan dataset buatan. Jalankan satu payload identik sebelum dan sesudah parameter binding simulatif.", images: { min: 1, max: 5 }, procedure: liveProcedure("pencarian produk", "daftar produk dan field pencarian", "lebih banyak produk dari maksud pencarian", "pemisahan struktur query dan nilai parameter"), skeleton: skeletonInjection },
    { id: "LIVE-2", caseId: "live-private-document", title: "Tugas Live Pilihan: Otorisasi objek privat", vulnerableFilename: "{NPM}-private-document-rentan.html", secureFilename: "{NPM}-private-document-aman.html", specification: "ATURAN MAHASISWA: Pilih SATU tugas yang ingin dikerjakan, sisanya anggap selesai. Bangun penyimpanan dokumen privat. Request objek sama harus ditolak setelah ownership check server simulatif.", images: { min: 1, max: 5 }, procedure: liveProcedure("dokumen privat", "identitas sesi dan daftar dokumen sintetis", "dokumen pemilik lain kembali pada response", "pemeriksaan ownership terhadap subject sesi"), skeleton: skeletonAccess },
    { id: "LIVE-3", caseId: "live-diagnostic-leak", title: "Pengayaan: Kebocoran debug pada endpoint diagnostik", vulnerableFilename: "{NPM}-diagnostic-endpoint-rentan.html", secureFilename: "{NPM}-diagnostic-endpoint-aman.html", specification: "Bangun endpoint diagnostik lokal dengan secret palsu. Error yang sama harus berubah dari bocor menjadi pesan generik setelah debug dimatikan.", images: { min: 1, max: 5 }, procedure: liveProcedure("endpoint diagnostik", "tombol pemicu error dan konfigurasi palsu", "stack serta secret sintetis muncul", "debug off, error sanitization, dan log internal terpisah"), skeleton: skeletonMisconfig },
    { id: "LIVE-4", caseId: "live-dependency-upgrade", title: "Pengayaan: Pembaruan komponen verifier token", vulnerableFilename: "{NPM}-dependency-verifier-rentan.html", secureFilename: "{NPM}-dependency-verifier-aman.html", specification: "Bangun dua implementasi verifier lokal. Token unsigned sama diterima implementasi lama dan ditolak implementasi hasil upgrade.", images: { min: 1, max: 5 }, procedure: liveProcedure("verifier dependency", "nomor versi dan field token sintetis", "verifier lama menerima token tanpa signature", "upgrade versi, pin algoritma, dan regression test"), skeleton: skeletonComponent }
  ];

  const runner = {
    "LAB-INJ": { vulnerable: E.runInjectionVulnerable, secure: E.runInjectionSecure },
    "LAB-BAC": { vulnerable: value => { const [requester, objectId] = String(value).split("|"); return E.runAccessVulnerable({ requester, objectId }); }, secure: value => { const [requester, objectId] = String(value).split("|"); return E.runAccessSecure({ requester, objectId }); } },
    "LAB-MIS": { vulnerable: E.runMisconfigVulnerable, secure: E.runMisconfigSecure },
    "LAB-COMP": { vulnerable: E.runComponentVulnerable, secure: E.runComponentSecure }
  };
  const getLab = id => { const lab = LABS.find(item => item.id === id); if (!lab) throw Error(`Lab tidak dikenal: ${id}`); return lab; };
  function createFlow(id) { getLab(id); return { id, prediction: "", input: "", lockedPayload: "", before: null, observation: "", cause: "", control: "", feedback: "", patched: false, canPatch: false, canRetest: false, after: null, retestPayload: "", comparison: "", conclusion: "" }; }
  function copy(flow) { return JSON.parse(JSON.stringify(flow)); }
  function recordPrediction(flow, prediction) { const next = copy(flow); next.prediction = String(prediction || ""); return next; }
  function runVulnerable(flow, input) { const next = copy(flow); next.input = String(input || ""); next.before = runner[next.id].vulnerable(next.input); if (next.before.exploited) { next.lockedPayload = next.input; next.canPatch = true; } else { next.lockedPayload = ""; next.canPatch = false; next.patched = false; next.canRetest = false; } return next; }
  function chooseControl(flow, controlId) { const next = copy(flow); const lab = getLab(next.id); const choice = lab.controls.find(item => item.id === controlId); if (!choice) throw Error("Kontrol tidak dikenal."); next.control = controlId; next.feedback = choice.feedback; next.patched = Boolean(next.canPatch && controlId === lab.correctControl); next.canRetest = next.patched; return next; }
  function retest(flow) { const next = copy(flow); if (!next.canRetest || !next.lockedPayload) throw Error("Retest masih terkunci."); next.retestPayload = next.lockedPayload; next.after = runner[next.id].secure(next.lockedPayload); return next; }
  function stageStatus(flow) { return [Boolean(flow.prediction.trim()), Boolean(flow.input.trim()), Boolean(flow.before && flow.before.exploited), Boolean(flow.observation.trim() && flow.cause.trim()), Boolean(flow.patched), Boolean(flow.after && !flow.after.exploited && flow.retestPayload === flow.lockedPayload), Boolean(flow.comparison.trim() && flow.conclusion.trim())]; }

  return { LABS, WORKED_EXAMPLES, LIVE_TASKS, createFlow, recordPrediction, runVulnerable, chooseControl, retest, stageStatus, getLab };
});
