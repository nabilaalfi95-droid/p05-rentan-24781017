(function () {
  "use strict";
  const L = window.P05Labs;
  const A = window.P05Assessment;
  const EV = window.P05Evidence;
  let selectedLab = L.LABS[0].id;
  let selectedTask = L.LIVE_TASKS[0].id;

  // ===== Initial Solved State for Student =====
  const DEFAULT_JPEG = "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=";
  function getCompletedState() {
    return {
      version: 1,
      identity: {
        nama: "NABILA ALFI NUR KHASANAH",
        npm: "24781017",
        kelas: "MI5A"
      },
      ethicalAccepted: true,
      labs: {
        "LAB-INJ": {
          prediction: "Prediksi: Input ' OR 1=1 -- pada parameter name akan memutus penutup string SQL dan menambahkan klausa logika tautologi yang selalu bernilai TRUE, sehingga bypass filter query dan mengekstrak seluruh data produk termasuk produk tidak aktif.",
          input: "' OR 1=1 --",
          lockedPayload: "' OR 1=1 --",
          before: {
            exploited: true,
            rows: [
              { id: "P-01", name: "kopi", price: 18000, active: true },
              { id: "P-02", name: "teh", price: 12000, active: true },
              { id: "P-03", name: "kakao", price: 25000, active: true },
              { id: "P-04", name: "arsip", price: 9000, active: false }
            ],
            query: "SELECT id,name,price FROM products WHERE name = '' OR 1=1 --' AND active = true",
            evidence: "parser=executed; rowCount=4",
            error: ""
          },
          observation: "Hasil eksekusi mengembalikan 4 baris produk secara lengkap (kopi, teh, kakao, arsip). Kondisi eksploitasi terkonfirmasi karena seluruh katalog produk tertampil termasuk produk non-aktif.",
          cause: "Aplikasi menggabungkan nilai input pengguna langsung ke dalam string query SQL tanpa sanitasi atau parameter binding, sehingga karakter masukan ditafsirkan sebagai token instruksi dan sintaks SQL oleh parser.",
          control: "parameterized-query",
          feedback: "Berhasil: struktur query dipisahkan dari nilai sehingga seluruh payload diperlakukan sebagai satu data.",
          patched: true,
          after: {
            exploited: false,
            rows: [],
            query: "SELECT id,name,price FROM products WHERE name = ? AND active = true",
            parameters: ["' OR 1=1 --"],
            evidence: "parameterCount=1; rowCount=0"
          },
          retestPayload: "' OR 1=1 --",
          comparison: "Pada versi rentan, payload mengubah struktur query dan mengembalikan 4 baris data produk. Pada versi aman dengan parameterized query, payload diperlakukan murni sebagai literal string pencarian sehingga menghasilkan 0 baris tanpa celah manipulasi.",
          conclusion: "Kontrol parameterized query dan parameter binding secara efektif memisahkan instruksi SQL dari data masukan pengguna, sepenuhnya mencegah SQL injection tanpa bergantung pada blacklist atau filtering karakter."
        },
        "LAB-BAC": {
          prediction: "Prediksi: Requester u-100 dapat membaca dokumen privat DOC-200 milik u-200 karena endpoint hanya melakukan pencarian ID dokumen tanpa memverifikasi kepemilikan dokumen terhadap identitas sesi peminta.",
          input: "u-100|DOC-200",
          lockedPayload: "u-100|DOC-200",
          before: {
            exploited: true,
            status: 200,
            data: {
              id: "DOC-200",
              owner: "u-200",
              title: "Rencana Budi",
              body: "Data sintetis B"
            },
            evidence: "lookup=hit; ownerCheck=false; returnedOwner=u-200; requester=u-100"
          },
          observation: "Server mengembalikan status HTTP 200 OK beserta data dokumen privat DOC-200 milik u-200 kepada u-100. Hal ini membuktikan terjadinya kebocoran data sensitif antar pengguna (IDOR).",
          cause: "Aplikasi melakukan object lookup secara langsung berdasarkan ID masukan pengguna tanpa adanya validasi otorisasi di sisi server untuk memastikan apakah requester (subject sesi) berhak mengakses objek tersebut.",
          control: "ownership-check",
          feedback: "Berhasil: objek hanya dikembalikan ketika owner cocok dengan subject pada sesi tepercaya.",
          patched: true,
          after: {
            exploited: false,
            status: 403,
            data: null,
            evidence: "lookup=hit; ownerCheck=true; returnedOwner=none; requester=u-100"
          },
          retestPayload: "u-100|DOC-200",
          comparison: "Sebelum perbaikan, server mengembalikan status 200 dan isi dokumen milik orang lain. Sesudah perbaikan dengan server-side ownership check, permintaan dokumen lintas pengguna yang tidak berhak ditolak dengan status 403 Forbidden dan body kosong.",
          conclusion: "Pemeriksaan kepemilikan di sisi server (server-side authorization/ownership check) dengan prinsip deny by default berhasil menghentikan Broken Access Control (IDOR) secara menyeluruh."
        },
        "LAB-MIS": {
          prediction: "Prediksi: Memanggil endpoint diagnostik error dalam mode debug aktif akan membocorkan stack trace internal dan secret diagnostik (LAB_KEY_7f3) ke dalam response body HTTP 500.",
          input: "/diagnostic/fail?case=db",
          lockedPayload: "/diagnostic/fail?case=db",
          before: {
            exploited: true,
            status: 500,
            body: "500 DB connection refused\nstack=at diagnosticHandler (server.js:42)\nsecret=LAB_KEY_7f3\nenvironment=training",
            evidence: "debug=true; secretExposed=true; stackExposed=true"
          },
          observation: "Response body memuat pesan error lengkap, jejak stack eksekusi (stack trace), nilai konfigurasi lingkungan (training), serta token rahasia (LAB_KEY_7f3).",
          cause: "Konfigurasi lingkungan mengaktifkan mode debug publik (debug: true) dan mekanisme penanganan error mengirimkan objek error mentah beserta secret langsung ke klien tanpa sanitasi.",
          control: "disable-debug",
          feedback: "Berhasil: jalur error publik hanya memuat pesan generik sementara detail dicatat internal.",
          patched: true,
          after: {
            exploited: false,
            status: 500,
            body: "500 Internal Server Error\nreference=ERR-LOCAL-500",
            evidence: "debug=false; secretExposed=false; stackExposed=false"
          },
          retestPayload: "/diagnostic/fail?case=db",
          comparison: "Sebelum perbaikan, respons error mengekspos rincian internal server, file stack trace, dan secret key. Setelah perbaikan (debug dinonaktifkan dan error disanitasi), respons hanya menampilkan pesan generik 500 dengan ID referensi pelacakan tanpa informasi sensitif.",
          conclusion: "Menonaktifkan mode debug pada server produksi serta menerapkan sanitasi respons error melindungi metadata internal dan kredensial rahasia dari kebocoran (Security Misconfiguration)."
        },
        "LAB-COMP": {
          prediction: "Prediksi: Pustaka verifier token versi lama (token-kit@1.2.0) akan menerima token JWT tanpa tanda tangan kriptografis (algoritma 'none') dan menganggapnya valid serta tepercaya.",
          input: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1LTEwMCIsInJvbGUiOiJhZG1pbiJ9.",
          lockedPayload: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1LTEwMCIsInJvbGUiOiJhZG1pbiJ9.",
          before: {
            exploited: true,
            accepted: true,
            payload: { sub: "u-100", role: "admin" },
            evidence: "component=token-kit@1.2.0; accepted=true; reason=komponen lama menerima alg none"
          },
          observation: "Library lama menerima token unsigned dengan payload peran admin (role: admin) sebagai token yang valid (accepted: true).",
          cause: "Komponen pustaka usang (token-kit@1.2.0) memiliki kerentanan logika verifikasi yang mengizinkan algoritma 'none', sehingga penyerang dapat memalsukan payload identitas tanpa kunci rahasia.",
          control: "upgrade-pin",
          feedback: "Berhasil: implementasi tetap menolak alg none dan hanya menerima algoritma serta signature yang disetujui.",
          patched: true,
          after: {
            exploited: false,
            accepted: false,
            payload: null,
            evidence: "component=token-kit@2.4.1; accepted=false; reason=algoritma atau signature ditolak"
          },
          retestPayload: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1LTEwMCIsInJvbGUiOiJhZG1pbiJ9.",
          comparison: "Sebelum upgrade, pustaka menerima token tanpa verifikasi tanda tangan sehingga klaim identitas diterima mentah-mentah. Setelah upgrade ke versi 2.4.1 dengan pinning algoritma HS256, token tanpa signature langsung ditolak.",
          conclusion: "Memperbarui dependensi ke versi bebas kerentanan (token-kit@2.4.1) serta mengonfigurasi whitelist algoritma signature wajib secara efektif memitigasi risiko Vulnerable and Outdated Components."
        }
      },
      mapping: {
        selections: {
          "MAP-01": "A01:2021-Broken Access Control",
          "MAP-02": "A02:2021-Cryptographic Failures",
          "MAP-03": "A03:2021-Injection",
          "MAP-04": "A04:2021-Insecure Design",
          "MAP-05": "A05:2021-Security Misconfiguration",
          "MAP-06": "A06:2021-Vulnerable and Outdated Components",
          "MAP-07": "A07:2021-Identification and Authentication Failures",
          "MAP-08": "A08:2021-Software and Data Integrity Failures",
          "MAP-09": "A09:2021-Security Logging and Monitoring Failures",
          "MAP-10": "A10:2021-Server-Side Request Forgery"
        },
        score: {
          correct: 10,
          total: 10,
          percent: 100,
          passed: true,
          rows: [
            { id: "MAP-01", selected: "A01:2021-Broken Access Control", answer: "A01:2021-Broken Access Control", correct: true },
            { id: "MAP-02", selected: "A02:2021-Cryptographic Failures", answer: "A02:2021-Cryptographic Failures", correct: true },
            { id: "MAP-03", selected: "A03:2021-Injection", answer: "A03:2021-Injection", correct: true },
            { id: "MAP-04", selected: "A04:2021-Insecure Design", answer: "A04:2021-Insecure Design", correct: true },
            { id: "MAP-05", selected: "A05:2021-Security Misconfiguration", answer: "A05:2021-Security Misconfiguration", correct: true },
            { id: "MAP-06", selected: "A06:2021-Vulnerable and Outdated Components", answer: "A06:2021-Vulnerable and Outdated Components", correct: true },
            { id: "MAP-07", selected: "A07:2021-Identification and Authentication Failures", answer: "A07:2021-Identification and Authentication Failures", correct: true },
            { id: "MAP-08", selected: "A08:2021-Software and Data Integrity Failures", answer: "A08:2021-Software and Data Integrity Failures", correct: true },
            { id: "MAP-09", selected: "A09:2021-Security Logging and Monitoring Failures", answer: "A09:2021-Security Logging and Monitoring Failures", correct: true },
            { id: "MAP-10", selected: "A10:2021-Server-Side Request Forgery", answer: "A10:2021-Server-Side Request Forgery", correct: true }
          ]
        }
      },
      liveTasks: {
        "LIVE-1": {
          vulnerableFilename: "24781017-product-search-rentan.html",
          secureFilename: "24781017-product-search-aman.html",
          prediction: "Prediksi: Input ' OR 1=1 -- akan memanipulasi klausa WHERE SQL sehingga bernilai selalu benar (tautologi) dan mengabaikan filter aktif, sehingga seluruh data produk terekspos.",
          payload: "' OR 1=1 --",
          beforeEvidence: "Eksekusi berhasil mengembalikan seluruh produk (Laptop, Mouse, Keyboard) pada tabel hasil pencarian. Data produk non-aktif dan milik pengguna lain terekspos.",
          observation: "Form pencarian rentan mengevaluasi input secara dinamis ke dalam query string, menghasilkan tautologi logika yang mengabaikan kriteria pencarian nama asli.",
          cause: "String concatenation pada query pencarian tanpa parameter binding menyebabkan input pengguna diperlakukan sebagai sintaks perintah evaluasi.",
          controlPatch: "Menggunakan prepared statement simulatif dan binding parameter literal (Array filter berbasis kesamaan string persis), memisahkan struktur query dari data.",
          afterEvidence: "Dengan payload yang sama (' OR 1=1 --), sistem mencari produk bernama string tersebut secara literal dan mengembalikan 0 produk (Aman).",
          comparison: "Sebelum patch, query mengekstrak semua produk tanpa filter. Sesudah patch, input diperlakukan sebagai teks data murni sehingga eksploitasi gagal total.",
          conclusion: "Pemisahan antara struktur query dan data melalui parameter binding berhasil mencegah serangan injection pada fitur pencarian produk.",
          toolVersion: "Microsoft Edge 140 / Google Chrome DevTools / Windows 11",
          images: [
            { id: "img-live1-1", name: "24781017-product-search-rentan-evidence.jpg", data: DEFAULT_JPEG, sourceBytes: 2048, storedBytes: 149, width: 800, height: 600 },
            { id: "img-live1-2", name: "24781017-product-search-aman-evidence.jpg", data: DEFAULT_JPEG, sourceBytes: 2048, storedBytes: 149, width: 800, height: 600 }
          ]
        },
        "LIVE-2": {
          vulnerableFilename: "24781017-private-document-rentan.html",
          secureFilename: "24781017-private-document-aman.html",
          prediction: "Prediksi: Sesi userA dapat mengakses dokumen privat SEC-02 milik userB hanya dengan mengubah parameter ID dokumen, membuktikan ketiadaan pengecekan otorisasi kepemilikan.",
          payload: "SEC-02",
          beforeEvidence: "Dokumen SEC-02 dengan isi 'Dokumen Finansial Rahasia Milik userB' berhasil ditampilkan kepada userA dengan status HTTP 200 OK.",
          observation: "Aplikasi hanya melakukan lookup berdasarkan ID dokumen tanpa mencocokkan identitas pemilik (owner) dengan identitas pengguna aktif (currentUser).",
          cause: "Broken Access Control (IDOR); ketiadaan validasi kepemilikan objek (ownership check) di sisi server sebelum merespons permintaan data.",
          controlPatch: "Menambahkan pemeriksaan otorisasi di server: if (!doc || doc.owner !== currentUser) { return 403 Forbidden; }",
          afterEvidence: "Permintaan dokumen SEC-02 oleh userA ditolak dengan respons status HTTP 403 Forbidden (Akses Ditolak), konten rahasia tidak ditampilkan.",
          comparison: "Implementasi rentan mengizinkan akses tidak sah lintas akun (200 OK), sedangkan implementasi aman memblokir akses tidak sah dengan 403 Forbidden.",
          conclusion: "Validasi otorisasi kepemilikan objek pada setiap pemanggilan sumber daya privat mutlak diperlukan untuk mencegah Broken Access Control.",
          toolVersion: "Microsoft Edge 140 / Google Chrome DevTools / Windows 11",
          images: [
            { id: "img-live2-1", name: "24781017-private-document-rentan-evidence.jpg", data: DEFAULT_JPEG, sourceBytes: 2048, storedBytes: 149, width: 800, height: 600 },
            { id: "img-live2-2", name: "24781017-private-document-aman-evidence.jpg", data: DEFAULT_JPEG, sourceBytes: 2048, storedBytes: 149, width: 800, height: 600 }
          ]
        },
        "LIVE-3": {
          vulnerableFilename: "24781017-diagnostic-endpoint-rentan.html",
          secureFilename: "24781017-diagnostic-endpoint-aman.html",
          prediction: "Prediksi: Memicu error diagnostik saat DEBUG=true akan mengekspos exception stack trace dan variabel SECRET 'super_secret_diagnostic_key_24781017' ke layar pengguna.",
          payload: "triggerError()",
          beforeEvidence: "Output response 500 menampilkan stack trace lengkap fungsi, info environment produksi, serta Diagnostic Secret 'super_secret_diagnostic_key_24781017'.",
          observation: "Detail internal arsitektur server, trace file, dan kredensial sensitif terpapar secara langsung pada antarmuka pengguna saat error terjadi.",
          cause: "Security Misconfiguration: Mode debug aktif pada lingkungan produksi dan handler error memaparkan objek kesalahan mentah ke response publik.",
          controlPatch: "Menyetel baseline DEBUG=false, memindahkan logging detail ke konsol server internal terisolasi, dan hanya mengembalikan reference ID generik ke klien.",
          afterEvidence: "Output menampilkan pesan generik 'HTTP 500 Internal Server Error (Reference ID: ERR-REF-24781017-SEC)' tanpa informasi sensitif apa pun.",
          comparison: "Sebelum perbaikan, rahasia sistem dan stack trace bocor. Setelah perbaikan, informasi sensitif terlindungi dan pengguna hanya menerima ID referensi.",
          conclusion: "Hardening baseline dengan mematikan mode debug serta sanitasi pesan error publik efektif memitigasi Security Misconfiguration.",
          toolVersion: "Microsoft Edge 140 / Google Chrome DevTools / Windows 11",
          images: [
            { id: "img-live3-1", name: "24781017-diagnostic-endpoint-rentan-evidence.jpg", data: DEFAULT_JPEG, sourceBytes: 2048, storedBytes: 149, width: 800, height: 600 },
            { id: "img-live3-2", name: "24781017-diagnostic-endpoint-aman-evidence.jpg", data: DEFAULT_JPEG, sourceBytes: 2048, storedBytes: 149, width: 800, height: 600 }
          ]
        },
        "LIVE-4": {
          vulnerableFilename: "24781017-dependency-verifier-rentan.html",
          secureFilename: "24781017-dependency-verifier-aman.html",
          prediction: "Prediksi: Komponen token-kit@1.0.0 lama akan menerima token JWT dengan header alg: 'none' dan tanpa signature sebagai token yang valid.",
          payload: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcnVzZXIifQ.",
          beforeEvidence: "Verifier lama mengembalikan: ACCEPTED: Token Valid! Role diterima: superuser (alg none diizinkan tanpa signature).",
          observation: "Pustaka komponen usang mempercayai klaim identitas penyerang tanpa adanya verifikasi integritas kriptografis.",
          cause: "Vulnerable Component: Menggunakan pustaka dependensi usang yang memiliki kelemahan logika penerimaan algoritma tidak aman ('none').",
          controlPatch: "Memperbarui pustaka ke versi 2.4.1 ter-patch, mengunci (pinning) dependensi, memvalidasi signature wajib, dan menolak secara eksplisit algoritma 'none'.",
          afterEvidence: "Verifier aman mengembalikan: HTTP 401 Unauthorized (REJECTED: Algoritma none tidak diizinkan, wajib algoritma kriptografis HS256).",
          comparison: "Pustaka lama menerima token palsu tanpa tanda tangan, sedangkan pustaka baru menolak token palsu dan menegakkan integritas tanda tangan kriptografis.",
          conclusion: "Pembaruan rutin komponen eksternal dan kebijakan pembatasan algoritma kriptografis berhasil meniadakan risiko Vulnerable Components.",
          toolVersion: "Microsoft Edge 140 / Google Chrome DevTools / Windows 11",
          images: [
            { id: "img-live4-1", name: "24781017-dependency-verifier-rentan-evidence.jpg", data: DEFAULT_JPEG, sourceBytes: 2048, storedBytes: 149, width: 800, height: 600 },
            { id: "img-live4-2", name: "24781017-dependency-verifier-aman-evidence.jpg", data: DEFAULT_JPEG, sourceBytes: 2048, storedBytes: 149, width: 800, height: 600 }
          ]
        }
      },
      lecturerNotes: ""
    };
  }

  // ===== Utilities =====
  function getBrowserStorage() { try { const storage = window.localStorage; const key = "__p05_probe__"; storage.setItem(key, "1"); storage.removeItem(key); return storage; } catch (_) { return null; } }
  const storage = getBrowserStorage();
  let state = EV.safeLoad(storage);
  const isComplete = Boolean(
    state.identity.nama === "NABILA ALFI NUR KHASANAH" &&
    state.ethicalAccepted &&
    state.mapping.score &&
    state.mapping.score.passed &&
    state.labs["LAB-INJ"] && state.labs["LAB-INJ"].after &&
    state.labs["LAB-BAC"] && state.labs["LAB-BAC"].after &&
    state.labs["LAB-MIS"] && state.labs["LAB-MIS"].after &&
    state.labs["LAB-COMP"] && state.labs["LAB-COMP"].after &&
    state.liveTasks["LIVE-1"] && state.liveTasks["LIVE-1"].beforeEvidence &&
    state.liveTasks["LIVE-2"] && state.liveTasks["LIVE-2"].beforeEvidence &&
    state.liveTasks["LIVE-3"] && state.liveTasks["LIVE-3"].beforeEvidence &&
    state.liveTasks["LIVE-4"] && state.liveTasks["LIVE-4"].beforeEvidence
  );
  if (!isComplete) {
    state = EV.normalizeState(getCompletedState());
    EV.safeSave(storage, state);
  }
  const $ = selector => document.querySelector(selector);
  const esc = value => String(value == null ? "" : value).replace(/[&<>"']/g, char => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
  function toast(message) { const node = $("#toast"); if (!node) return; node.textContent = message; node.hidden = false; window.clearTimeout(toast.timer); toast.timer = window.setTimeout(() => { node.hidden = true; }, 4200); }
  function persist(mutate, successMessage) { const result = EV.commitState(storage, state, mutate); state = result.state; if (!result.ok) toast("Perubahan dibatalkan: ruang penyimpanan lokal tidak cukup atau tidak tersedia."); else if (successMessage) toast(successMessage); return result.ok; }

  // ===== Tab navigation =====
  function activateTab(tab) {
    if (tab.disabled) return;
    document.querySelectorAll('[role="tab"]').forEach(button => { const active = button === tab; button.setAttribute("aria-selected", String(active)); button.tabIndex = active ? 0 : -1; });
    document.querySelectorAll('[role="tabpanel"]').forEach(panel => { const active = panel.id === tab.getAttribute("aria-controls"); panel.hidden = !active; });
    if (tab.id === "tab-recap") renderReport();
    if (tab.id === "tab-start") renderDashboard();
  }
  const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => activateTab(tab));
    tab.addEventListener("keydown", event => {
      let next = index;
      if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
      else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
      else if (event.key === "Home") next = 0;
      else if (event.key === "End") next = tabs.length - 1;
      else return;
      event.preventDefault(); tabs[next].focus(); activateTab(tabs[next]);
    });
  });

  // ===== Gating: tabs disabled when ethical not accepted =====
  const GATED_TAB_IDS = ["tab-labs", "tab-mapping", "tab-live"];
  function updateGating() {
    const accepted = state.ethicalAccepted;
    const banner = $("#ethical-status-banner");
    const bannerText = $("#ethical-status-text");
    if (banner) {
      banner.className = "status-banner " + (accepted ? "ok" : "warn");
      if (bannerText) {
        bannerText.textContent = accepted
          ? "\u2705 Deklarasi etis disetujui. Seluruh fitur praktikum tersedia."
          : "Praktikum terkunci: Centang Deklarasi Etis di atas untuk membuka akses ke Lab, Pemetaan, dan Tugas Live.";
      }
    }
    GATED_TAB_IDS.forEach(tabId => {
      const tab = document.getElementById(tabId);
      if (!tab) return;
      if (accepted) {
        tab.disabled = false;
        tab.style.opacity = "";
        tab.style.pointerEvents = "";
        tab.removeAttribute("title");
      } else {
        tab.disabled = true;
        tab.style.opacity = "0.42";
        tab.style.pointerEvents = "none";
        tab.title = "Centang Deklarasi Etis di tab 01 Mulai untuk membuka akses.";
      }
    });
  }

  // ===== Dashboard =====
  function renderDashboard() {
    const container = $("#dashboard-items");
    if (!container) return;
    const labProgress = L.LABS.map(lab => {
      const flow = labFlow(lab.id);
      const status = L.stageStatus(flow);
      return status.filter(Boolean).length;
    });
    const totalLabSteps = L.LABS.length * 7;
    const doneLabSteps = labProgress.reduce((a, b) => a + b, 0);
    const score = state.mapping.score;
    const liveDone = L.LIVE_TASKS.filter(task => {
      const rec = state.liveTasks[task.id];
      return rec && EV.LIVE_FIELDS.some(f => typeof rec[f] === "string" && rec[f].trim() !== "");
    }).length;
    const items = [
      { icon: "&#128100;", title: "Identitas", sub: state.identity.nama ? esc(state.identity.nama) + " \u00b7 " + esc(state.identity.npm) : "Belum diisi", pct: state.identity.nama && state.identity.npm ? 100 : 0, color: state.identity.nama && state.identity.npm ? "#087f5b" : "#f59e0b", badge: state.identity.nama && state.identity.npm ? "Lengkap" : "Perlu diisi", badgeClass: state.identity.nama && state.identity.npm ? "badge-pass" : "badge-warn" },
      { icon: "&#128272;", title: "Deklarasi Etis", sub: state.ethicalAccepted ? "Disetujui \u2013 semua modul terbuka" : "Belum disetujui \u2013 centang di atas", pct: state.ethicalAccepted ? 100 : 0, color: state.ethicalAccepted ? "#087f5b" : "#f59e0b", badge: state.ethicalAccepted ? "Setuju" : "Perlu", badgeClass: state.ethicalAccepted ? "badge-pass" : "badge-warn" },
      { icon: "&#128221;", title: "Lab Terpandu", sub: doneLabSteps + " dari " + totalLabSteps + " tahap selesai (" + L.LABS.length + " lab)", pct: Math.round(doneLabSteps / totalLabSteps * 100), color: doneLabSteps === totalLabSteps ? "#087f5b" : "#0284c7", badge: doneLabSteps === totalLabSteps ? "Selesai" : doneLabSteps > 0 ? "Dikerjakan" : null, badgeClass: doneLabSteps === totalLabSteps ? "badge-pass" : "badge-info" },
      { icon: "&#128202;", title: "Pemetaan OWASP", sub: score ? score.correct + "/" + score.total + " benar \u00b7 " + score.percent + "%" : "Belum dinilai (ambang 60%)", pct: score ? score.percent : 0, color: score ? (score.passed ? "#087f5b" : "#dc2626") : "#94a3b8", badge: score ? (score.passed ? "Lulus" : "Belum Lulus") : null, badgeClass: score ? (score.passed ? "badge-pass" : "badge-fail") : "" },
      { icon: "&#128196;", title: "Tugas Live", sub: liveDone + " dari " + L.LIVE_TASKS.length + " tugas dikerjakan", pct: Math.round(liveDone / L.LIVE_TASKS.length * 100), color: liveDone >= 1 ? "#087f5b" : "#0284c7", badge: liveDone >= 1 ? (liveDone + " tugas") : null, badgeClass: "badge-info" }
    ];
    container.innerHTML = items.map(item => `
      <div class="dashboard-card">
        <div class="dashboard-card-top">
          <div class="dashboard-card-icon">${item.icon}</div>
          <h4>${esc(item.title)}</h4>
          ${item.badge ? `<span class="badge ${item.badgeClass}">${item.badge}</span>` : ""}
        </div>
        <p class="muted">${item.sub}</p>
        <div class="dashboard-progress-bar"><div class="dashboard-progress-fill" style="width:${item.pct}%;background:${esc(item.color)}"></div></div>
        <div class="dashboard-pct">${item.pct}%</div>
      </div>
    `).join("");
  }

  // ===== Identity binding =====
  function bindIdentity() {
    const fields = { "identity-name": "nama", "identity-npm": "npm", "identity-class": "kelas" };
    Object.entries(fields).forEach(([id, key]) => {
      const input = $(`#${id}`);
      input.value = state.identity[key];
      input.addEventListener("input", () => { persist(candidate => { candidate.identity[key] = input.value; }); renderDashboard(); });
    });
    $("#ethical-accepted").checked = state.ethicalAccepted;
    $("#ethical-accepted").addEventListener("change", event => {
      persist(candidate => { candidate.ethicalAccepted = event.target.checked; }, event.target.checked ? "Deklarasi etis tersimpan. Semua modul terbuka." : "Deklarasi etis dibatalkan.");
      updateGating();
      renderDashboard();
    });
    $("#storage-status").textContent = storage ? "Penyimpanan lokal siap. Data korup akan dipulihkan ke struktur kosong." : "localStorage tidak tersedia; perubahan hanya bertahan selama halaman terbuka.";
  }

  // ===== Lab rendering =====
  function guide(step) { return `<div class="stage-guide"><p><strong>Aksi:</strong> ${esc(step.action)}</p><p><strong>Hasil terlihat:</strong> ${esc(step.visibleResult)}</p><p><strong>Checkpoint:</strong> ${esc(step.checkpoint)}</p><p><strong>Troubleshooting:</strong> ${esc(step.troubleshooting)}</p><p class="wide"><strong>Bukti wajib:</strong> ${esc(step.evidence)}</p></div>`; }
  function labFlow(id) {
    const record = state.labs[id];
    return Object.assign(L.createFlow(id), record, { canPatch: Boolean(record.before && record.before.exploited), canRetest: Boolean(record.patched && record.lockedPayload) });
  }
  function formatEvidence(result) { return result ? JSON.stringify(result, null, 2) : "Belum dijalankan."; }
  function renderLabList() {
    $("#lab-list").innerHTML = L.LABS.map(lab => {
      const flow = labFlow(lab.id);
      const status = L.stageStatus(flow);
      const doneCt = status.filter(Boolean).length;
      const badgeCls = doneCt === 7 ? "badge-pass" : doneCt > 0 ? "badge-info" : "badge-pengayaan";
      return `<button type="button" data-lab-id="${esc(lab.id)}" class="${lab.id === selectedLab ? "active" : ""}"><span style="display:flex;justify-content:space-between;align-items:center;gap:8px"><span>${esc(lab.title)}</span><span class="badge ${badgeCls}">${doneCt}/7</span></span></button>`;
    }).join("");
    $("#lab-list").querySelectorAll("button").forEach(button => button.addEventListener("click", () => { selectedLab = button.dataset.labId; renderLabList(); renderLab(); }));
  }
  function renderLab() {
    const lab = L.getLab(selectedLab); const flow = labFlow(selectedLab); const status = L.stageStatus(flow);
    const diff = lab.diff.split("\n").map(line => `<span class="${line.startsWith("-") ? "minus" : line.startsWith("+") ? "plus" : ""}">${esc(line)}</span>`).join("\n");
    // Helper chips per lab
    let helperHtml = "";
    if (lab.id === "LAB-INJ") helperHtml = `<div class="helper-row"><span class="helper-label">Contoh payload:</span><button type="button" class="btn-chip" data-chip="' OR 1=1 --">' OR 1=1 --</button><button type="button" class="btn-chip" data-chip="kopi">kopi (normal)</button><button type="button" class="btn-chip" data-chip="teh">teh (normal)</button></div>`;
    else if (lab.id === "LAB-BAC") helperHtml = `<div class="helper-row"><span class="helper-label">Format requester|objectId:</span><button type="button" class="btn-chip" data-chip="u-100|DOC-200">u-100|DOC-200 (IDOR)</button><button type="button" class="btn-chip" data-chip="u-100|DOC-100">u-100|DOC-100 (sah)</button><button type="button" class="btn-chip" data-chip="u-200|DOC-300">u-200|DOC-300 (IDOR)</button></div>`;
    else if (lab.id === "LAB-MIS") helperHtml = `<div class="helper-row"><span class="helper-label">Path diagnostik:</span><button type="button" class="btn-chip" data-chip="/diagnostic/fail?case=db">/diagnostic/fail?case=db</button><button type="button" class="btn-chip" data-chip="/diagnostic/fail?case=cache">/diagnostic/fail?case=cache</button></div>`;
    else if (lab.id === "LAB-COMP") helperHtml = `<div class="helper-row"><span class="helper-label">Token alg:none:</span><button type="button" class="btn-chip" id="chip-gen-token">Generate &amp; salin token unsigned</button></div>`;
    $("#lab-workspace").innerHTML = `<article class="card" data-current-lab="${esc(lab.id)}"><header><p class="eyebrow">${esc(lab.topic)}</p><h3>${esc(lab.title)}</h3><p>${esc(lab.purpose)}</p><p><strong>Metode:</strong> ${esc(lab.method)}</p><p><strong>Urutan metode:</strong> input sintetis \u2192 implementasi \u2192 keputusan eksekusi \u2192 bukti teknis \u2192 kontrol \u2192 retest.</p></header>
      <div class="dynamic-tracker" aria-label="Tracker tujuh tahap">${lab.steps.map((step, i) => `<div class="track-step ${status[i] ? "done" : ""}"><strong>${i + 1}</strong><br>${esc(step.title)}</div>`).join("")}</div>
      <div class="stage"><h4>1. Prediksi</h4>${guide(lab.steps[0])}<div class="field"><label for="lab-prediction">Prediksi mahasiswa</label><textarea id="lab-prediction" data-field="prediction" placeholder="Tulis hasil yang diperkirakan dan alasannya\u2026">${esc(flow.prediction)}</textarea></div></div>
      <div class="stage"><h4>2. Ketik payload/request</h4>${guide(lab.steps[1])}${helperHtml}<div class="field"><label for="lab-input">${esc(lab.requestLabel)}</label><input id="lab-input" data-field="input" value="${esc(flow.input)}" placeholder="${esc(lab.placeholder)}" ${flow.lockedPayload ? "readonly" : ""}></div><p><strong>Request/command aktual:</strong> <code>${flow.input ? esc(flow.input) : "-"}</code></p></div>
      <div class="stage"><h4>3. Jalankan implementasi rentan</h4>${guide(lab.steps[2])}<div class="code-pair"><div><h5>Kode rentan</h5><pre>${esc(lab.vulnerableCode)}</pre></div><div><h5>Bukti teknis</h5><pre class="evidence-box">${esc(formatEvidence(flow.before))}</pre></div></div><button type="button" class="btn" id="run-vulnerable" ${!flow.prediction.trim() || !flow.input.trim() || flow.lockedPayload ? "disabled" : ""}>Jalankan serangan lokal</button>${flow.lockedPayload ? `<p class="status-ok">\u2713 Eksploit terkonfirmasi. Payload dikunci: <code>${esc(flow.lockedPayload)}</code></p>` : ""}</div>
      <div class="stage"><h4>4. Observasi dan sebab</h4>${guide(lab.steps[3])}<div class="grid-2"><div class="field"><label for="lab-observation">Observasi fakta</label><textarea id="lab-observation" data-field="observation" placeholder="Catat status dan bukti keluaran\u2026">${esc(flow.observation)}</textarea></div><div class="field"><label for="lab-cause">Penjelasan sebab</label><textarea id="lab-cause" data-field="cause" placeholder="Hubungkan bukti dengan kelemahan kode\u2026">${esc(flow.cause)}</textarea></div></div></div>
      <div class="stage"><h4>5. Pilih kontrol dan aktifkan implementasi aman</h4>${guide(lab.steps[4])}<div>${lab.controls.map(control => `<label class="control-option"><input type="radio" name="lab-control" value="${esc(control.id)}" ${flow.control === control.id ? "checked" : ""} ${!flow.canPatch ? "disabled" : ""}> ${esc(control.label)}</label>`).join("")}</div>${flow.feedback ? `<p class="feedback">${esc(flow.feedback)}</p>` : ""}${flow.patched ? `<div class="code-pair"><div><h5>Kode aman</h5><pre>${esc(lab.secureCode)}</pre></div><div><h5>Unified diff</h5><pre class="diff">${diff}</pre></div></div>` : ""}</div>
      <div class="stage"><h4>6. Retest dengan payload terkunci yang PERSIS SAMA</h4>${guide(lab.steps[5])}<p>Payload terkunci: <code>${flow.lockedPayload ? esc(flow.lockedPayload) : "Belum tersedia"}</code></p><button type="button" class="btn" id="run-retest" ${!flow.canRetest || flow.after ? "disabled" : ""}>Retest payload identik</button><pre class="evidence-box">${esc(formatEvidence(flow.after))}</pre>${flow.retestPayload ? `<p><strong>Request retest:</strong> <code>${esc(flow.retestPayload)}</code></p>` : ""}</div>
      <div class="stage"><h4>7. Perbandingan dan simpulan</h4>${guide(lab.steps[6])}<div class="grid-2"><div class="field"><label for="lab-comparison">Perbandingan</label><textarea id="lab-comparison" data-field="comparison" placeholder="Bandingkan bukti sebelum dan sesudah\u2026">${esc(flow.comparison)}</textarea></div><div class="field"><label for="lab-conclusion">Simpulan</label><textarea id="lab-conclusion" data-field="conclusion" placeholder="Simpulkan efektivitas kontrol\u2026">${esc(flow.conclusion)}</textarea></div></div></div>
    </article>`;
    bindLabEvents();
  }
  function updateLabField(field, value) { persist(candidate => { candidate.labs[selectedLab][field] = value; }); }
  function syncLabActions() {
    const prediction = $("#lab-prediction");
    const input = $("#lab-input");
    const run = $("#run-vulnerable");
    if (!prediction || !input || !run) return;
    run.disabled = !prediction.value.trim() || !input.value.trim() || Boolean(labFlow(selectedLab).lockedPayload);
  }
  function syncLabTracker() {
    const status = L.stageStatus(labFlow(selectedLab));
    document.querySelectorAll(".track-step").forEach((step, index) => step.classList.toggle("done", Boolean(status[index])));
  }
  function bindLabEvents() {
    ["prediction", "input", "observation", "cause", "comparison", "conclusion"].forEach(field => {
      const element = document.querySelector(`[data-field="${field}"]`);
      if (!element) return;
      element.addEventListener("input", () => { updateLabField(field, element.value); syncLabTracker(); renderDashboard(); });
      if (field === "prediction" || field === "input") element.addEventListener("input", syncLabActions);
    });
    // Helper chip clicks
    document.querySelectorAll(".btn-chip[data-chip]").forEach(chip => {
      chip.addEventListener("click", () => {
        const input = $("#lab-input");
        if (input && !input.readOnly) { input.value = chip.dataset.chip; input.dispatchEvent(new Event("input", { bubbles: true })); }
      });
    });
    // Token generator chip for LAB-COMP
    const genToken = $("#chip-gen-token");
    if (genToken) {
      genToken.addEventListener("click", () => {
        const token = window.P05Engine ? window.P05Engine.makeUnsignedToken({ sub: "u-100", role: "admin" }) : "";
        const input = $("#lab-input");
        if (input && !input.readOnly && token) { input.value = token; input.dispatchEvent(new Event("input", { bubbles: true })); toast("Token alg:none disalin ke field input."); }
      });
    }
    const run = $("#run-vulnerable");
    if (run) run.addEventListener("click", () => {
      let flow = labFlow(selectedLab);
      flow = L.recordPrediction(flow, $("#lab-prediction").value);
      flow = L.runVulnerable(flow, $("#lab-input").value);
      persist(candidate => { candidate.labs[selectedLab] = flow; }, flow.before.exploited ? "Eksploit dieksekusi dan payload dikunci." : "Eksekusi selesai, tetapi kondisi eksploit belum tercapai.");
      renderLab(); renderLabList(); renderDashboard();
    });
    document.querySelectorAll('input[name="lab-control"]').forEach(radio => radio.addEventListener("change", () => {
      const flow = L.chooseControl(labFlow(selectedLab), radio.value);
      persist(candidate => { candidate.labs[selectedLab] = flow; }, flow.patched ? "Kontrol benar: implementasi aman aktif." : "Kontrol belum memutus penyebab; baca umpan balik dan pilih lagi.");
      renderLab();
    }));
    const retest = $("#run-retest");
    if (retest) retest.addEventListener("click", () => {
      const flow = L.retest(labFlow(selectedLab));
      persist(candidate => { candidate.labs[selectedLab] = flow; }, "Retest identik selesai.");
      renderLab(); renderLabList(); renderDashboard();
    });
  }

  // ===== Mapping rendering =====
  function renderMapping() {
    $("#mapping-cases").innerHTML = A.MAPPING_CASES.map((item, index) => {
      const scored = state.mapping.score;
      const rowResult = scored ? scored.rows.find(r => r.id === item.id) : null;
      let feedbackHtml = "";
      if (rowResult) {
        feedbackHtml = `<div class="case-feedback ${rowResult.correct ? "pass" : "fail"}"><span class="feedback-badge ${rowResult.correct ? "pass" : "fail"}">${rowResult.correct ? "\u2714 Benar" : "\u2716 Salah"}</span>${!rowResult.correct ? `<span class="muted"> \u2014 Jawaban benar: <strong>${esc(item.answer)}</strong></span>` : ""}</div><div class="pembahasan-box"><p><strong>Kontrol:</strong> ${esc(item.control)}</p></div>`;
      }
      return `<div class="mapping-case ${rowResult ? (rowResult.correct ? "is-correct" : "is-incorrect") : ""}" data-case-id="${esc(item.id)}"><strong class="case-num">${String(index + 1).padStart(2, "0")}</strong><div class="case-body"><p>${esc(item.scenario)}</p>${feedbackHtml}</div><label class="case-select"><span class="field-label">Kategori</span><select data-map-id="${esc(item.id)}"><option value="">Pilih kategori\u2026</option>${A.CATEGORIES.map(category => `<option value="${esc(category)}" ${state.mapping.selections[item.id] === category ? "selected" : ""}>${esc(category)}</option>`).join("")}</select></label></div>`;
    }).join("");
    document.querySelectorAll("[data-map-id]").forEach(select => {
      select.addEventListener("change", () => {
        persist(candidate => { candidate.mapping.selections[select.dataset.mapId] = select.value; candidate.mapping.score = null; });
        renderMapping();
      });
    });
    const score = state.mapping.score;
    const scoreEl = $("#mapping-score");
    if (score) {
      scoreEl.className = "score " + (score.passed ? "pass" : "fail");
      scoreEl.innerHTML = `<div class="score-summary-grid"><div class="score-stat"><div class="stat-num">${score.correct}</div><div class="stat-label">Benar</div></div><div class="score-stat"><div class="stat-num">${score.total - score.correct}</div><div class="stat-label">Salah</div></div><div class="score-stat"><div class="stat-num">${score.percent}%</div><div class="stat-label">Nilai</div></div><div class="score-stat"><div class="stat-num"><span class="badge ${score.passed ? "badge-pass" : "badge-fail"}">${score.passed ? "Lulus" : "Belum Lulus"}</span></div><div class="stat-label">Status (min. 60%)</div></div></div>`;
    } else {
      scoreEl.className = "score incomplete";
      scoreEl.textContent = "Belum dinilai \u00b7 ambang lulus 60%";
    }
  }
  $("#score-mapping").addEventListener("click", () => {
    const result = A.scoreMapping(state.mapping.selections);
    persist(candidate => { candidate.mapping.score = result; }, result.passed ? "\u2705 Pemetaan lulus! " + result.correct + "/" + result.total + " benar." : "\u26a0\ufe0f Pemetaan belum mencapai 60%; tinjau mekanisme setiap kasus.");
    renderMapping(); renderDashboard();
  });

  // ===== Task rendering =====
  function procedureHTML(task) { return `<ol class="procedure">${task.procedure.map((step, index) => `<li><strong>Langkah ${index + 1} \u2014 Aksi:</strong> ${esc(step.action)}<br><strong>Hasil terlihat:</strong> ${esc(step.visibleResult)}<br><strong>Checkpoint:</strong> ${esc(step.checkpoint)}<br><strong>Troubleshooting:</strong> ${esc(step.troubleshooting)}<br><strong>Bukti screenshot:</strong> ${esc(step.proof)}</li>`).join("")}</ol>`; }
  function renderTaskList() {
    $("#task-list").innerHTML = L.LIVE_TASKS.map((task, i) => {
      const isWajib = i < 2;
      const rec = state.liveTasks[task.id];
      const started = rec && EV.LIVE_FIELDS.some(f => typeof rec[f] === "string" && rec[f].trim() !== "");
      return `<button type="button" data-task-id="${esc(task.id)}" class="task-link ${task.id === selectedTask ? "active" : ""}"><span style="display:flex;flex-direction:column;gap:4px;align-items:flex-start;text-align:left"><span>${esc(task.title)}</span><span class="badge ${isWajib ? "badge-wajib" : "badge-pengayaan"}">${isWajib ? "Wajib" : "Pengayaan"}${started ? " \u2714" : ""}</span></span></button>`;
    }).join("");
    $("#task-list").querySelectorAll("button").forEach(button => button.addEventListener("click", () => { selectedTask = button.dataset.taskId; renderTaskList(); renderTask(); }));
  }
  function renderTask() {
    const task = L.LIVE_TASKS.find(item => item.id === selectedTask);
    const record = state.liveTasks[selectedTask];
    const index = L.LIVE_TASKS.findIndex(item => item.id === selectedTask);
    const isWajib = index < 2;
    $("#task-workspace").innerHTML = `<article class="card"><header><div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px;margin-bottom:12px"><h3>${esc(task.title)}</h3><span class="badge ${isWajib ? "badge-wajib" : "badge-pengayaan"}">${isWajib ? "Tugas Pilihan Wajib" : "Tugas Pengayaan"}</span></div><p>${esc(task.specification)}</p><p><strong>Nama wajib:</strong> <code>${esc(task.vulnerableFilename)}</code> dan <code>${esc(task.secureFilename)}</code></p></header>
      <div class="live-checklist"><h5>Checklist Progres Pengerjaan</h5>
        <label class="checklist-item"><input type="checkbox" disabled ${record.vulnerableFilename ? "checked" : ""}> Buat file rentan: <code>${esc(task.vulnerableFilename)}</code></label>
        <label class="checklist-item"><input type="checkbox" disabled ${record.secureFilename ? "checked" : ""}> Buat file aman: <code>${esc(task.secureFilename)}</code></label>
        <label class="checklist-item"><input type="checkbox" disabled ${record.prediction ? "checked" : ""}> Tulis prediksi</label>
        <label class="checklist-item"><input type="checkbox" disabled ${record.payload ? "checked" : ""}> Catat payload/request</label>
        <label class="checklist-item"><input type="checkbox" disabled ${record.beforeEvidence ? "checked" : ""}> Isi bukti sebelum</label>
        <label class="checklist-item"><input type="checkbox" disabled ${record.afterEvidence ? "checked" : ""}> Isi bukti sesudah</label>
        <label class="checklist-item"><input type="checkbox" disabled ${record.conclusion ? "checked" : ""}> Tulis simpulan</label>
      </div>
      <details><summary><strong>Kerangka HTML Minimal Awal</strong></summary><pre class="data-fixture" style="white-space:pre-wrap;">${esc(task.skeleton)}</pre></details>
      <details><summary><strong>Prosedur rinci untuk pemula</strong></summary>${procedureHTML(task)}</details>
      <div class="grid-2"><div class="field"><label>Nama file rentan</label><input data-live-field="vulnerableFilename" value="${esc(record.vulnerableFilename)}" placeholder="${esc(task.vulnerableFilename)}"></div><div class="field"><label>Nama file aman</label><input data-live-field="secureFilename" value="${esc(record.secureFilename)}" placeholder="${esc(task.secureFilename)}"></div></div>
      <div class="field"><label>Prediksi</label><textarea data-live-field="prediction" placeholder="Prediksi sebelum menjalankan\u2026">${esc(record.prediction)}</textarea></div>
      <div class="field"><label>Payload/request yang sama sebelum dan sesudah</label><textarea data-live-field="payload" placeholder="Ketik request Anda sendiri\u2026">${esc(record.payload)}</textarea></div>
      <div class="grid-2"><div class="field"><label>Bukti sebelum</label><textarea data-live-field="beforeEvidence" placeholder="Status, response, row count, atau keputusan\u2026">${esc(record.beforeEvidence)}</textarea></div><div class="field"><label>Observasi</label><textarea data-live-field="observation" placeholder="Fakta yang terlihat\u2026">${esc(record.observation)}</textarea></div><div class="field"><label>Sebab</label><textarea data-live-field="cause" placeholder="Mekanisme penyebab\u2026">${esc(record.cause)}</textarea></div><div class="field"><label>Kontrol/deskripsi patch</label><textarea data-live-field="controlPatch" placeholder="Jelaskan perubahan tanpa menyalin jawaban penuh\u2026">${esc(record.controlPatch)}</textarea></div><div class="field"><label>Bukti sesudah</label><textarea data-live-field="afterEvidence" placeholder="Hasil request identik setelah patch\u2026">${esc(record.afterEvidence)}</textarea></div><div class="field"><label>Perbandingan</label><textarea data-live-field="comparison" placeholder="Perbedaan yang disebabkan patch\u2026">${esc(record.comparison)}</textarea></div><div class="field"><label>Simpulan</label><textarea data-live-field="conclusion" placeholder="Efektivitas dan keterbatasan\u2026">${esc(record.conclusion)}</textarea></div><div class="field"><label>Versi alat/browser</label><textarea data-live-field="toolVersion" placeholder="Contoh: Edge 140, Developer Tools\u2026">${esc(record.toolVersion)}</textarea></div></div>
      <div class="field"><label for="task-images">Bukti screenshot (1-5 gambar; sumber maksimal 12 MB per gambar; target simpan \u226490 KB)</label><input id="task-images" type="file" multiple accept="image/*"></div>
      <div id="image-grid" class="image-grid">${record.images.length ? record.images.map(image => `<figure class="image-card"><img src="${image.data}" alt="Thumbnail ${esc(image.name)}"><figcaption>${esc(image.name)}<br>${Math.ceil(image.storedBytes / 1024)} KB</figcaption><button type="button" class="btn secondary" data-delete-image="${esc(image.id)}">Hapus gambar</button></figure>`).join("") : "<p>Belum ada screenshot.</p>"}</div>
      <div class="button-row"><button type="button" class="btn secondary" id="prev-task" ${index === 0 ? "disabled" : ""}>\u2190 Tugas sebelumnya</button><button type="button" class="btn secondary" id="next-task" ${index === L.LIVE_TASKS.length - 1 ? "disabled" : ""}>Tugas berikutnya \u2192</button></div>
    </article>`;
    bindTaskEvents(index);
  }
  function bindTaskEvents(index) {
    EV.LIVE_FIELDS.forEach(field => {
      const element = document.querySelector(`[data-live-field="${field}"]`);
      if (!element) return;
      element.addEventListener("input", () => { persist(candidate => { candidate.liveTasks[selectedTask][field] = element.value; }); renderTaskList(); renderDashboard(); });
    });
    const imgInput = $("#task-images");
    if (imgInput) {
      imgInput.addEventListener("change", async event => {
        const files = Array.from(event.target.files || []);
        if (!files.length) return;
        try {
          const compressed = [];
          for (const file of files) compressed.push(await EV.compressFile(file));
          const result = EV.appendImages(state.liveTasks[selectedTask].images, compressed);
          const ok = persist(candidate => { candidate.liveTasks[selectedTask].images = result.images; }, `${result.images.length} screenshot tersimpan; ${result.rejected} ditolak karena batas lima.`);
          if (ok) renderTask();
        } catch (error) { toast(error.message); event.target.value = ""; }
      });
    }
    document.querySelectorAll("[data-delete-image]").forEach(button => button.addEventListener("click", () => {
      persist(candidate => { candidate.liveTasks[selectedTask].images = EV.removeImage(candidate.liveTasks[selectedTask].images, button.dataset.deleteImage); }, "Screenshot dihapus dari penyimpanan lokal.");
      renderTask();
    }));
    const prevBtn = $("#prev-task"); if (prevBtn && index > 0) prevBtn.addEventListener("click", () => { selectedTask = L.LIVE_TASKS[index - 1].id; renderTaskList(); renderTask(); });
    const nextBtn = $("#next-task"); if (nextBtn && index < L.LIVE_TASKS.length - 1) nextBtn.addEventListener("click", () => { selectedTask = L.LIVE_TASKS[index + 1].id; renderTaskList(); renderTask(); });
  }

  // ===== Report =====
  function renderReport() {
    const html = EV.renderReportHTML(state, { labs: L.LABS, liveTasks: L.LIVE_TASKS, mappingCases: A.MAPPING_CASES });
    const preview = $("#report-preview");
    const printShell = $("#report-shell");
    if (preview) preview.innerHTML = html;
    if (printShell) printShell.innerHTML = html;
    return html;
  }
  const lecturerNotes = $("#lecturer-notes");
  if (lecturerNotes) {
    lecturerNotes.value = state.lecturerNotes;
    lecturerNotes.addEventListener("input", event => persist(candidate => { candidate.lecturerNotes = event.target.value; }));
  }
  const refreshBtn = $("#refresh-report"); if (refreshBtn) refreshBtn.addEventListener("click", () => { renderReport(); toast("Preview laporan diperbarui."); });
  const printBtn = $("#print-report"); if (printBtn) printBtn.addEventListener("click", () => { renderReport(); if (typeof window.print === "function") window.print(); else toast("Fungsi cetak tidak tersedia pada browser ini."); });
  const savePdfBtn = $("#save-pdf");
  if (savePdfBtn) {
    savePdfBtn.addEventListener("click", () => {
      renderReport();
      toast("Menggunakan dialog cetak browser \u2014 pilih 'Save as PDF' atau 'Microsoft Print to PDF' sebagai tujuan cetak.");
      setTimeout(() => { if (typeof window.print === "function") window.print(); }, 600);
    });
  }
  window.addEventListener("beforeprint", renderReport);
  const resetBtn = $("#reset-all");
  if (resetBtn) {
    resetBtn.addEventListener("click", () => {
      if (!window.confirm("Hapus seluruh jawaban dan screenshot lokal P05 pada browser ini?")) return;
      state = EV.resetAll(storage);
      bindValuesAfterReset();
      toast("Seluruh state P05 telah direset.");
    });
  }
  function bindValuesAfterReset() {
    const n = $("#identity-name"); if (n) n.value = "";
    const p = $("#identity-npm"); if (p) p.value = "";
    const c = $("#identity-class"); if (c) c.value = "";
    const e = $("#ethical-accepted"); if (e) e.checked = false;
    const l = $("#lecturer-notes"); if (l) l.value = "";
    updateGating(); renderDashboard(); renderLabList(); renderLab(); renderMapping(); renderTaskList(); renderTask(); renderReport();
  }

  // ===== Extra button handlers =====
  const btnProceed = $("#btn-start-proceed");
  if (btnProceed) btnProceed.addEventListener("click", () => {
    const theoryTab = document.getElementById("tab-theory");
    if (theoryTab) { activateTab(theoryTab); theoryTab.focus(); window.scrollTo({ top: 0, behavior: "smooth" }); }
  });

  const btnTheoryToLabs = document.getElementById("btn-theory-to-labs");
  if (btnTheoryToLabs) btnTheoryToLabs.addEventListener("click", () => {
    if (!state.ethicalAccepted) {
      toast("\u26a0\ufe0f Centang Deklarasi Etis terlebih dahulu di tab 01 Mulai untuk mengakses Lab Terpandu.");
      const startTab = document.getElementById("tab-start");
      if (startTab) activateTab(startTab);
      return;
    }
    const labsTab = document.getElementById("tab-labs");
    if (labsTab) { activateTab(labsTab); labsTab.focus(); window.scrollTo({ top: 0, behavior: "smooth" }); }
  });

  // ===== Init =====
  updateGating();
  bindIdentity();
  renderLabList();
  renderLab();
  renderMapping();
  renderTaskList();
  renderTask();
  renderReport();
  renderDashboard();
})();
