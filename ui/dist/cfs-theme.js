/* Theme/accent bootstrap: must run before first paint to avoid a flash when
   the stored theme differs from the CSS default. Loaded as a normal
   same-origin script so the locked-down CSP (script-src 'self', no inline)
   keeps holding. Mirrors lib/theme.svelte.ts keys. */
(function () {
  try {
    var a = localStorage.getItem("cfs_accent");
    if (a && a !== "cyan") document.documentElement.dataset.accent = a;
  } catch (e) {}
  try {
    var k = "cfs_theme";
    var s = localStorage.getItem(k);
    var t = s;
    if (t !== "light" && t !== "dark") {
      t =
        window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
          ? "light"
          : "dark";
    }
    if (t === "light" || t === "dark") {
      document.documentElement.dataset.theme = t;
      document.documentElement.style.colorScheme = t;
    }
  } catch (e) {}
})();
