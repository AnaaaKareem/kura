// Kura UI v2 ("Ledger") Shared Interactions
document.addEventListener("DOMContentLoaded", function () {
    // -------------------------------------------------------------------------
    // 1. Office Room Filter by Building
    // -------------------------------------------------------------------------
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

    // -------------------------------------------------------------------------
    // 2. Recovery Codes Copy & Print
    // -------------------------------------------------------------------------
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

    // Print the current document for buttons marked with data-print.
    document.querySelectorAll("[data-print]").forEach(function (button) {
        button.addEventListener("click", function () { window.print(); });
    });

    // -------------------------------------------------------------------------
    // 3. Theme Management (Light "kura", Dark "kura-dark", System "kura-system")
    // -------------------------------------------------------------------------
    const allowedThemes = ["light", "dark", "system"];
    const themeNames = { light: "kura", dark: "kura-dark", system: "kura-system" };
    let savedTheme = localStorage.getItem("kura-theme") || "system";
    if (!allowedThemes.includes(savedTheme)) savedTheme = "system";

    function applyTheme(themeKey) {
        if (!allowedThemes.includes(themeKey)) return;
        localStorage.setItem("kura-theme", themeKey);
        document.documentElement.setAttribute("data-theme", themeNames[themeKey]);

        // Sync dropdown selectors if present
        document.querySelectorAll("[data-theme-selector]").forEach(function (el) {
            el.value = themeKey;
        });
        // Sync radio buttons if present
        document.querySelectorAll('input[name="kura-theme-choice"]').forEach(function (el) {
            el.checked = (el.value === themeKey);
        });
    }

    // Apply on load
    applyTheme(savedTheme);

    // Listen to changes on selectors or radios
    document.querySelectorAll("[data-theme-selector]").forEach(function (el) {
        el.addEventListener("change", function () { applyTheme(el.value); });
    });
    document.querySelectorAll('input[name="kura-theme-choice"]').forEach(function (el) {
        el.addEventListener("change", function () {
            if (el.checked) applyTheme(el.value);
        });
    });

    // -------------------------------------------------------------------------
    // 4. Mobile Sidebar Close on Link Click
    // -------------------------------------------------------------------------
    const sidebarToggle = document.getElementById("kura-sidebar-toggle");
    document.querySelectorAll("[data-close-sidebar]").forEach(function (link) {
        link.addEventListener("click", function () {
            if (sidebarToggle) sidebarToggle.checked = false;
        });
    });

    // Dismiss flash messages without inline style changes.
    document.addEventListener("click", function (event) {
        const dismissBtn = event.target.closest("[data-dismiss-message]");
        if (dismissBtn) {
            const messageItem = dismissBtn.closest("[data-message-item]");
            if (messageItem) {
                messageItem.remove();
            }
        }
    });

    // -------------------------------------------------------------------------
    // 6. Accessible Confirmation Dialog (<dialog id="k-confirm">)
    // -------------------------------------------------------------------------
    const confirmModal = document.getElementById("k-confirm");
    let pendingSubmitForm = null;

    if (confirmModal) {
        const confirmMsg = confirmModal.querySelector("[data-confirm-message]");
        const confirmSubmitBtn = confirmModal.querySelector("[data-confirm-submit]");
        const confirmCancelBtn = confirmModal.querySelector("[data-confirm-cancel]");

        if (confirmCancelBtn) {
            confirmCancelBtn.addEventListener("click", function () {
                pendingSubmitForm = null;
                confirmModal.close();
            });
        }

        if (confirmSubmitBtn) {
            confirmSubmitBtn.addEventListener("click", function () {
                if (pendingSubmitForm) {
                    const formToSubmit = pendingSubmitForm;
                    pendingSubmitForm = null;
                    confirmModal.close();
                    formToSubmit.dataset.confirmed = "true";
                    if (typeof formToSubmit.requestSubmit === "function") {
                        formToSubmit.requestSubmit();
                    } else {
                        formToSubmit.submit();
                    }
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

        if (confirmModal && typeof confirmModal.showModal === "function") {
            event.preventDefault();
            pendingSubmitForm = form;
            const msgEl = confirmModal.querySelector("[data-confirm-message]");
            if (msgEl) msgEl.textContent = message;

            const tone = form.getAttribute("data-confirm-tone") || (submitter && submitter.getAttribute("data-confirm-tone")) || "error";
            const submitBtn = confirmModal.querySelector("[data-confirm-submit]");
            if (submitBtn) {
                if (tone === "primary") {
                    submitBtn.className = "btn btn-primary btn-sm";
                } else {
                    submitBtn.className = "btn btn-error btn-sm";
                }
            }

            confirmModal.showModal();
            const cancelBtn = confirmModal.querySelector("[data-confirm-cancel]");
            if (cancelBtn) cancelBtn.focus();
        } else {
            // Fallback for browsers without <dialog>
            if (!window.confirm(message)) {
                event.preventDefault();
            }
        }
    });

    // Disable the submit button after a POST submits so users cannot trigger duplicate writes.
    document.addEventListener("submit", function (event) {
        const form = event.target;
        if (!form || form.method.toUpperCase() !== "POST" || event.defaultPrevented) return;
        const submitBtn = event.submitter || form.querySelector('button[type="submit"]:not([data-no-loading])');
        if (submitBtn && !submitBtn.disabled && !submitBtn.hasAttribute("data-no-loading")) {
            submitBtn.disabled = true;
            submitBtn.classList.add("loading", "loading-spinner");
            window.addEventListener("pageshow", function () {
                submitBtn.disabled = false;
                submitBtn.classList.remove("loading", "loading-spinner");
            }, { once: true });
        }
    });

    // -------------------------------------------------------------------------
    // 8. Focus Form Error Summary on Page Load
    // -------------------------------------------------------------------------
    const errorSummary = document.querySelector("[data-form-error-summary]");
    if (errorSummary) {
        errorSummary.focus();
    }

    // -------------------------------------------------------------------------
    // 9. Assessment Authoring Dynamic Groups
    // -------------------------------------------------------------------------
    const delivery = document.getElementById("id_delivery_mode");
    if (!delivery) return;

    function updateDelivery() {
        const online = delivery.value !== "paper_scanned";
        document.querySelectorAll("[data-online-only]").forEach(function (section) { section.hidden = !online; });
        document.querySelectorAll("[data-scanned-only]").forEach(function (section) { section.hidden = online; });
    }

    function updateCard(card) {
        const type = card.querySelector("select[name$='-type']");
        if (!type) return;
        card.querySelectorAll("[data-question-group]").forEach(function (group) {
            const active = group.dataset.questionGroup === type.value;
            group.hidden = !active;
            group.querySelectorAll("input, textarea, select").forEach(function (input) { input.disabled = !active; });
        });
    }

    function prepareCards() {
        document.querySelectorAll("[data-question-card]").forEach(function (card) {
            updateCard(card);
            card.querySelectorAll("[data-question-group]").forEach(function (group) {
                if (group.dataset.rowsReady) return;
                group.dataset.rowsReady = "true";
                group.querySelectorAll("[data-question-row]").forEach(function (row, index) {
                    const filled = Array.from(row.querySelectorAll("input")).some(function (input) {
                        return input.type === "checkbox" ? input.checked : input.value.trim() !== "";
                    });
                    row.hidden = !filled && index >= (group.dataset.questionGroup === "multiple_choice" ? 2 : 1);
                });
            });
        });
    }

    delivery.addEventListener("change", updateDelivery);
    document.addEventListener("change", function (event) {
        const card = event.target.closest("[data-question-card]");
        if (card) updateCard(card);
    });
    document.addEventListener("click", function (event) {
        const move = event.target.closest("[data-move-question]");
        if (move) {
            const card = move.closest("[data-question-card]");
            const list = card.parentElement;
            if (move.dataset.moveQuestion === "up" && card.previousElementSibling) {
                list.insertBefore(card, card.previousElementSibling);
            } else if (move.dataset.moveQuestion === "down" && card.nextElementSibling) {
                list.insertBefore(card.nextElementSibling, card);
            }
            list.querySelectorAll("[data-question-card]").forEach(function (question, index) {
                const orderInput = question.querySelector("input[name$='-ORDER']");
                if (orderInput) orderInput.value = index + 1;
            });
            move.focus();
            return;
        }
        const remove = event.target.closest("[data-remove-row]");
        if (remove) {
            const row = remove.closest("[data-question-row]");
            row.querySelectorAll("input").forEach(function (input) {
                if (input.type === "checkbox") input.checked = false;
                else input.value = "";
            });
            row.hidden = true;
            const addBtn = remove.closest("[data-question-group]").querySelector("[data-add-row]");
            if (addBtn) addBtn.focus();
            return;
        }
        const button = event.target.closest("[data-add-row]");
        if (!button) return;
        const row = button.parentElement.querySelector("[data-question-row][hidden]");
        if (row) {
            row.hidden = false;
            const firstInput = row.querySelector("input");
            if (firstInput) firstInput.focus();
        }
    });
    document.body.addEventListener("htmx:afterSwap", prepareCards);
    updateDelivery();
    prepareCards();
});
