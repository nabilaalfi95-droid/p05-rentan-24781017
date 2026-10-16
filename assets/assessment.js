(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.P05Assessment = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";
  const PASS_PERCENT = 60;
  const CATEGORIES = [
    "A01:2021-Broken Access Control", "A02:2021-Cryptographic Failures", "A03:2021-Injection",
    "A04:2021-Insecure Design", "A05:2021-Security Misconfiguration", "A06:2021-Vulnerable and Outdated Components",
    "A07:2021-Identification and Authentication Failures", "A08:2021-Software and Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures", "A10:2021-Server-Side Request Forgery"
  ];
  const MAPPING_CASES = [
    { id: "MAP-01", scenario: "API invoice mengembalikan invoice pelanggan lain ketika angka ID pada path diubah; sesi tetap milik pengguna biasa.", answer: CATEGORIES[0], control: "Periksa ownership setiap objek di server dan deny by default." },
    { id: "MAP-02", scenario: "Database menyimpan nomor identitas dalam teks biasa sehingga backup yang bocor langsung dapat dibaca.", answer: CATEGORIES[1], control: "Enkripsi data sensitif at rest dengan manajemen kunci terpisah." },
    { id: "MAP-03", scenario: "Filter laporan menyambung nilai departemen ke query sehingga ekspresi logika tambahan mengubah hasil.", answer: CATEGORIES[2], control: "Gunakan parameterized query dan binding bertipe." },
    { id: "MAP-04", scenario: "Fitur transfer tidak memiliki batas transaksi atau langkah persetujuan walau abuse case telah diketahui.", answer: CATEGORIES[3], control: "Tambahkan kontrol desain untuk abuse case sebelum implementasi." },
    { id: "MAP-05", scenario: "Server produksi menjalankan mode debug dan response error memuat stack serta nilai konfigurasi.", answer: CATEGORIES[4], control: "Gunakan baseline hardening, debug off, dan error sanitization." },
    { id: "MAP-06", scenario: "Aplikasi memakai pustaka pemroses arsip versi lama yang tercantum memiliki kerentanan eksekusi.", answer: CATEGORIES[5], control: "Inventaris dependency, upgrade versi tetap, pin, dan regression test." },
    { id: "MAP-07", scenario: "Token reset sandi dapat dipakai berulang dan tidak kedaluwarsa setelah sandi berhasil diubah.", answer: CATEGORIES[6], control: "Token sekali pakai, pendek umur, dan dicabut setelah konsumsi." },
    { id: "MAP-08", scenario: "Pipeline pembaruan memasang paket tanpa verifikasi signature atau provenance artefak.", answer: CATEGORIES[7], control: "Verifikasi integritas, provenance, dan jalur build tepercaya." },
    { id: "MAP-09", scenario: "Percobaan login gagal tidak dicatat sehingga serangan berulang tidak menghasilkan alert.", answer: CATEGORIES[8], control: "Log kejadian keamanan, lindungi log, dan buat alert terukur." },
    { id: "MAP-10", scenario: "Fitur impor URL pada server dapat mengambil alamat metadata internal yang dipilih pengguna.", answer: CATEGORIES[9], control: "Allowlist tujuan, blok jaringan internal, dan validasi setelah redirect." }
  ];
  function scoreMapping(selections) {
    const rows = MAPPING_CASES.map(item => ({ id: item.id, selected: String((selections || {})[item.id] || ""), answer: item.answer, correct: String((selections || {})[item.id] || "") === item.answer }));
    const correct = rows.filter(row => row.correct).length;
    const percent = Math.round(correct / MAPPING_CASES.length * 100);
    return { correct, total: MAPPING_CASES.length, percent, passed: percent >= PASS_PERCENT, rows };
  }
  return { PASS_PERCENT, CATEGORIES, MAPPING_CASES, scoreMapping };
});
