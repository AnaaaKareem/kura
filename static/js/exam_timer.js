// Client-side exam timer countdown, stage styling and tab focus loss detection without inline scripts
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
    let announcedStage = null;

    // Create or find live region for time stage announcements
    let liveAnnouncer = document.getElementById("timer-announcer");
    if (!liveAnnouncer) {
        liveAnnouncer = document.createElement("div");
        liveAnnouncer.id = "timer-announcer";
        liveAnnouncer.className = "sr-only";
        liveAnnouncer.setAttribute("aria-live", "polite");
        document.body.appendChild(liveAnnouncer);
    }

    function updateTimer() {
        const now = new Date().getTime();
        const diff = expiresAt - now;

        if (diff <= 0) {
            timerElem.innerText = "00:00:00 (Expired)";
            timerElem.classList.remove("text-warning");
            timerElem.classList.add("text-error");
            window.location.reload();
            return;
        }

        // Timer stages per Design System v2 Section 8.9:
        // > 5m: neutral
        // <= 5m: text-warning + announce once in polite live region
        // <= 1m: text-error + announce once in assertive live region
        if (diff <= 60 * 1000) {
            timerElem.classList.remove("text-warning");
            timerElem.classList.add("text-error");
            if (announcedStage !== "critical") {
                announcedStage = "critical";
                liveAnnouncer.setAttribute("aria-live", "assertive");
                liveAnnouncer.textContent = "1 minute left in assessment.";
            }
        } else if (diff <= 5 * 60 * 1000) {
            timerElem.classList.remove("text-error");
            timerElem.classList.add("text-warning");
            if (announcedStage !== "warning" && announcedStage !== "critical") {
                announcedStage = "warning";
                liveAnnouncer.setAttribute("aria-live", "polite");
                liveAnnouncer.textContent = "5 minutes left in assessment.";
            }
        } else {
            timerElem.classList.remove("text-warning", "text-error");
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
