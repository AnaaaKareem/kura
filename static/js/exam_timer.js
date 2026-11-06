// Client-side exam timer countdown and tab focus loss detection without inline scripts
document.addEventListener("DOMContentLoaded", function () {
    const timerElem = document.getElementById("exam-timer");
    if (!timerElem) return;

    // Tell the student if an autosave fails instead of leaving an old success message visible.
    document.body.addEventListener("htmx:responseError", function () {
        const status = document.getElementById("autosave-status");
        if (status) status.textContent = "Not saved. Check your answer and try again.";
    });

    const expiresAtStr = timerElem.getAttribute("data-expires-at");
    const autosaveUrl = timerElem.getAttribute("data-autosave-url");
    const csrfToken = timerElem.getAttribute("data-csrf-token");

    if (!expiresAtStr) return;

    const expiresAt = new Date(expiresAtStr).getTime();

    function updateTimer() {
        const now = new Date().getTime();
        const diff = expiresAt - now;

        if (diff <= 0) {
            timerElem.innerText = "00:00:00 (Expired)";
            window.location.reload();
            return;
        }

        const hours = Math.floor(diff / (1000 * 60 * 60));
        const mins = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const secs = Math.floor((diff % (1000 * 60)) / 1000);

        timerElem.innerText =
            (hours > 0 ? String(hours).padStart(2, "0") + ":" : "") +
            String(mins).padStart(2, "0") + ":" +
            String(secs).padStart(2, "0");
    }

    setInterval(updateTimer, 1000);
    updateTimer();

    // Tab switch / window blur focus loss reporting
    window.addEventListener("blur", function () {
        if (!autosaveUrl || !csrfToken) return;
        const formData = new FormData();
        formData.append("csrfmiddlewaretoken", csrfToken);
        formData.append("focus_lost", "1");
        fetch(autosaveUrl, {
            method: "POST",
            body: formData,
        });
    });
});
