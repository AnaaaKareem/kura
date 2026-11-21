// Kura shared interactions: colour theme, confirmation dialog, copy/print helpers.
// Loaded from an external file because the Content Security Policy blocks inline scripts.
document.addEventListener("DOMContentLoaded", function () {
    // 1. Colour theme: "light", "dark", or "system" (follows the operating system).
    const allowedThemes = ["light", "dark", "system"];
    const colourScheme = window.matchMedia("(prefers-color-scheme: dark)");

    function applyTheme(choice) {
        if (!allowedThemes.includes(choice)) choice = "system";
        try {
            localStorage.setItem("kura-theme", choice);
        } catch (error) {
            // Private browsing can block storage; the theme then lasts for this page only.
        }
        let resolved = choice;
        if (choice === "system") resolved = colourScheme.matches ? "dark" : "light";
        document.documentElement.setAttribute("data-bs-theme", resolved);
        document.querySelectorAll("[data-theme-selector]").forEach(function (select) {
            select.value = choice;
        });
    }

    let savedTheme = "system";
    try {
        savedTheme = localStorage.getItem("kura-theme") || "system";
    } catch (error) {
        savedTheme = "system";
    }
    applyTheme(savedTheme);
    document.querySelectorAll("[data-theme-selector]").forEach(function (select) {
        select.addEventListener("change", function () { applyTheme(select.value); });
    });
    // When the choice is "system", follow operating system changes while the page is open.
    colourScheme.addEventListener("change", function () {
        if ((localStorage.getItem("kura-theme") || "system") === "system") applyTheme("system");
    });

    // 2. Office room filter by building (staff creation form).
    const building = document.querySelector("[data-office-building]");
    const room = document.querySelector("[data-office-room]");
    const officeRooms = document.getElementById("office-rooms");
    if (building && room && officeRooms) {
        const rooms = JSON.parse(officeRooms.textContent);
        const updateRooms = function () {
            const selected = room.value;
            room.replaceChildren(new Option("Select a room", ""));
            rooms.forEach(function (item) {
                if (String(item.building_id) === building.value) {
                    room.add(new Option(item.name, item.id));
                }
            });
            room.value = selected;
            if (room.selectedIndex < 0) room.selectedIndex = 0;
        };
        building.addEventListener("change", updateRooms);
        updateRooms();
    }

    // 3. Recovery codes: copy and print.
    const copyRecoveryCodes = document.querySelector("[data-copy-recovery-codes]");
    const recoveryStatus = document.querySelector("[data-recovery-status]");
    if (copyRecoveryCodes && recoveryStatus) {
        copyRecoveryCodes.addEventListener("click", async function () {
            const codes = Array.from(document.querySelectorAll("[data-recovery-code]"))
                .map(function (code) { return code.textContent.trim(); }).join("\n");
            try {
                await navigator.clipboard.writeText(codes);
                recoveryStatus.textContent = "Recovery codes copied.";
            } catch (error) {
                recoveryStatus.textContent = "Could not copy codes. Select and copy them manually.";
            }
        });
    }
    const printRecoveryCodes = document.querySelector("[data-print-recovery-codes]");
    if (printRecoveryCodes) {
        printRecoveryCodes.addEventListener("click", function () { window.print(); });
    }
    document.querySelectorAll("[data-print]").forEach(function (button) {
        button.addEventListener("click", function () { window.print(); });
    });

    // 4. Block a link or button (data-requires) until the referenced checkbox is ticked.
    document.querySelectorAll("[data-requires]").forEach(function (control) {
        const checkbox = document.querySelector(control.getAttribute("data-requires"));
        if (!checkbox) return;
        const syncRequired = function () {
            control.classList.toggle("disabled", !checkbox.checked);
            control.setAttribute("aria-disabled", checkbox.checked ? "false" : "true");
        };
        control.addEventListener("click", function (event) {
            if (!checkbox.checked) {
                event.preventDefault();
                checkbox.focus();
            }
        });
        checkbox.addEventListener("change", syncRequired);
        syncRequired();
    });

    // 5. Copy text from a referenced element into the clipboard.
    document.querySelectorAll("[data-copy]").forEach(function (button) {
        button.addEventListener("click", async function () {
            const target = document.querySelector(button.getAttribute("data-copy"));
            const status = button.parentElement ? button.parentElement.querySelector("[data-copy-status]") : null;
            if (!target) return;
            try {
                await navigator.clipboard.writeText(target.textContent.trim());
                if (status) status.textContent = "Copied.";
            } catch (error) {
                if (status) status.textContent = "Copy failed. Select and copy it manually.";
            }
        });
    });

    // 6. Full screen view of the live attendance code and QR panel.
    document.querySelectorAll("[data-fullscreen]").forEach(function (button) {
        const target = document.querySelector(button.getAttribute("data-fullscreen"));
        if (!target || !target.requestFullscreen) return;
        button.addEventListener("click", function () {
            if (document.fullscreenElement === target) {
                document.exitFullscreen();
            } else {
                target.requestFullscreen();
            }
        });
    });

    // 7. Dismiss buttons for notices and flash messages.
    document.addEventListener("click", function (event) {
        const dismissTarget = event.target.closest("[data-dismiss-target]");
        if (dismissTarget) {
            const element = document.querySelector(dismissTarget.getAttribute("data-dismiss-target"));
            if (element) element.remove();
            return;
        }
        const dismissMessage = event.target.closest("[data-dismiss-message]");
        if (dismissMessage) {
            const item = dismissMessage.closest("[data-message-item]");
            if (item) item.remove();
        }
    });

    // 8. Confirmation dialog (Bootstrap modal) for forms marked with data-confirm-action.
    const confirmElement = document.getElementById("k-confirm");
    const confirmModal = confirmElement && window.bootstrap ? new window.bootstrap.Modal(confirmElement) : null;
    let pendingSubmitForm = null;

    if (confirmElement) {
        const confirmSubmit = confirmElement.querySelector("[data-confirm-submit]");
        const confirmCancel = confirmElement.querySelector("[data-confirm-cancel]");
        if (confirmCancel) {
            confirmCancel.addEventListener("click", function () { pendingSubmitForm = null; });
        }
        confirmElement.addEventListener("hidden.bs.modal", function () { pendingSubmitForm = null; });
        if (confirmSubmit) {
            confirmSubmit.addEventListener("click", function () {
                if (!pendingSubmitForm) return;
                const form = pendingSubmitForm;
                pendingSubmitForm = null;
                confirmModal.hide();
                // One-shot flag so the re-submit below skips this dialog.
                form.dataset.confirmed = "true";
                if (typeof form.requestSubmit === "function") {
                    form.requestSubmit();
                } else {
                    form.submit();
                }
            });
        }
    }

    document.addEventListener("submit", function (event) {
        const form = event.target;
        if (!form) return;
        const submitter = event.submitter || form.querySelector('button[type="submit"][data-confirm-action]');
        const message = form.getAttribute("data-confirm-action") || (submitter && submitter.getAttribute("data-confirm-action"));
        if (!message) return;
        if (form.dataset.confirmed === "true") {
            form.removeAttribute("data-confirmed");
            return;
        }
        if (confirmModal) {
            event.preventDefault();
            pendingSubmitForm = form;
            confirmElement.querySelector("[data-confirm-message]").textContent = message;
            const tone = form.getAttribute("data-confirm-tone") || (submitter && submitter.getAttribute("data-confirm-tone")) || "error";
            const submitButton = confirmElement.querySelector("[data-confirm-submit]");
            submitButton.className = tone === "primary" ? "btn btn-primary" : "btn btn-danger";
            confirmModal.show();
        } else if (!window.confirm(message)) {
            event.preventDefault();
        }
    });

    // 9. Disable the submit button after a POST so a double click cannot write twice.
    document.addEventListener("submit", function (event) {
        const form = event.target;
        if (!form || form.method.toUpperCase() !== "POST" || event.defaultPrevented) return;
        const submitButton = event.submitter || form.querySelector('button[type="submit"]:not([data-no-loading])');
        if (submitButton && !submitButton.disabled && !submitButton.hasAttribute("data-no-loading")) {
            submitButton.disabled = true;
            window.addEventListener("pageshow", function () { submitButton.disabled = false; }, { once: true });
        }
    });

    // 10. Move focus to the form error summary when a page loads with errors.
    const errorSummary = document.querySelector("[data-form-error-summary]");
    if (errorSummary) errorSummary.focus();
});
