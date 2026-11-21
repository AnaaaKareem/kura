// Apply the saved colour theme before the first paint so there is no flash of the wrong theme.
// Bootstrap reads the data-bs-theme attribute, which is either "light" or "dark".
(function () {
  var saved = "system";
  try {
    saved = localStorage.getItem("kura-theme") || "system";
  } catch (e) {
    saved = "system";
  }
  var resolved = saved;
  if (saved !== "light" && saved !== "dark") {
    resolved = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-bs-theme", resolved);
})();
