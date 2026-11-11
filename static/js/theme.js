// Keep the assessment builder usable without inline scripts or unsafe HTML insertion.
document.addEventListener("DOMContentLoaded", function () {
    // Filter office rooms by building without trusting the browser for validation.
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
    // Copy the codes shown on this page without sending them to the server.
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

    // Open the browser's print dialog while the one-time codes are visible.
    const printRecoveryCodes = document.querySelector("[data-print-recovery-codes]");
    if (printRecoveryCodes) {
        printRecoveryCodes.addEventListener("click", function () { window.print(); });
    }
    // Apply the saved theme, or follow the device setting for a new browser.
    const themeSelector = document.querySelector("[data-theme-selector]");
    const savedTheme = localStorage.getItem("kura-theme") || "system";
    const allowedThemes = ["light", "dark", "system"];
    const selectedTheme = allowedThemes.includes(savedTheme) ? savedTheme : "system";
    const themeNames = { light: "kura", dark: "kura-dark", system: "kura-system" };

    document.documentElement.dataset.theme = themeNames[selectedTheme];
    if (themeSelector) {
        themeSelector.value = selectedTheme;
        themeSelector.addEventListener("change", function () {
            if (!allowedThemes.includes(themeSelector.value)) return;
            localStorage.setItem("kura-theme", themeSelector.value);
            document.documentElement.dataset.theme = themeNames[themeSelector.value];
        });
    }

    // Turn the current route name into a short, readable breadcrumb without exposing record details.
    const breadcrumbCurrent = document.querySelector("[data-breadcrumb-current]");
    if (breadcrumbCurrent) {
        breadcrumbCurrent.textContent = breadcrumbCurrent.textContent.replaceAll("_", " ");
    }

    // Keep the mobile sidebar state available to keyboard users through its checkbox.
    const sidebarToggle = document.getElementById("kura-sidebar-toggle");
    document.querySelectorAll("[data-close-sidebar]").forEach(function (link) {
        link.addEventListener("click", function () {
            if (sidebarToggle) sidebarToggle.checked = false;
        });
    });

    // Keep destructive actions confirmed without using an inline event attribute.
    document.querySelectorAll("[data-confirm-action]").forEach(function (control) {
        const eventName = control.tagName === "FORM" ? "submit" : "click";
        control.addEventListener(eventName, function (event) {
            if (!window.confirm(control.dataset.confirmAction)) event.preventDefault();
        });
    });

    // Pages without the assessment builder still need the theme and sidebar controls above.
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
                question.querySelector("input[name$='-ORDER']").value = index + 1;
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
            remove.closest("[data-question-group]").querySelector("[data-add-row]").focus();
            return;
        }
        const button = event.target.closest("[data-add-row]");
        if (!button) return;
        const row = button.parentElement.querySelector("[data-question-row][hidden]");
        if (row) { row.hidden = false; row.querySelector("input").focus(); }
    });
    document.body.addEventListener("htmx:afterSwap", prepareCards);
    updateDelivery();
    prepareCards();
});
