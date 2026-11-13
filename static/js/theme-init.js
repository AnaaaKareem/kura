(function () {
  try {
    var theme = localStorage.getItem("kura-theme") || "kura-system";
    document.documentElement.setAttribute("data-theme", theme);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "kura-system");
  }
})();
