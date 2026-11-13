// Apply the saved theme before the first paint to prevent a light flash.
(function () {
  var themeMap = {
    light: "kura",
    dark: "kura-dark",
    system: "kura-system",
    kura: "kura",
    "kura-dark": "kura-dark",
    "kura-system": "kura-system",
  };
  try {
    var saved = localStorage.getItem("kura-theme") || "system";
    var resolved = themeMap[saved] || "kura-system";
    document.documentElement.setAttribute("data-theme", resolved);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "kura-system");
  }
})();
