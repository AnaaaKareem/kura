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

    // Live word counters for written-answer textareas.
    document.querySelectorAll("[data-word-counter-input]").forEach(function (textarea) {
        const counterId = textarea.getAttribute("data-word-counter-target");
        const counter = counterId ? document.getElementById(counterId) : null;
        if (!counter) return;
        const maxWords = parseInt(textarea.getAttribute("data-max-words") || "0", 10);
        const updateWordCount = function () {
            const trimmed = textarea.value.trim();
            const count = trimmed ? trimmed.split(/\s+/).length : 0;
            counter.textContent = maxWords > 0 ? count + " / " + maxWords + " words" : count + " words";
            counter.classList.toggle("text-error", maxWords > 0 && count > maxWords);
        };
        textarea.addEventListener("input", updateWordCount);
        updateWordCount();
    });

    // Enforce one-question-at-a-time navigation when backtracking is disabled.
    const questionsWrap = document.querySelector("[data-exam-questions]");
    if (questionsWrap && questionsWrap.getAttribute("data-allow-backtracking") === "false") {
        const cards = Array.from(questionsWrap.querySelectorAll("[data-question-card]"));
        const nextBtn = document.querySelector("[data-next-question]");
        const stepLabel = document.querySelector("[data-question-step]");
        const storageKey = "kura-exam-step:" + window.location.pathname;
        let currentIndex = parseInt(sessionStorage.getItem(storageKey) || "0", 10);
        if (isNaN(currentIndex) || currentIndex < 0 || currentIndex >= cards.length) {
            currentIndex = 0;
        }
        const renderStep = function () {
            cards.forEach(function (card, idx) {
                card.hidden = idx !== currentIndex;
            });
            if (stepLabel) {
                stepLabel.textContent = "Question " + (currentIndex + 1) + " of " + cards.length;
            }
            if (nextBtn) {
                nextBtn.hidden = currentIndex >= cards.length - 1;
            }
            sessionStorage.setItem(storageKey, String(currentIndex));
        };
        if (nextBtn) {
            nextBtn.addEventListener("click", function () {
                if (currentIndex < cards.length - 1) {
                    currentIndex += 1;
                    renderStep();
                }
            });
        }
        renderStep();
    }
});
