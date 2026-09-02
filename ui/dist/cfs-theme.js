(function () {
  try {
    var a = localStorage.getItem("cfs_accent");
    if (a === "violet" || a === "green" || a === "amber")
      document.documentElement.dataset.accent = a;
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
