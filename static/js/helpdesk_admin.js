(function () {
    "use strict";

    const byId = (id) => document.getElementById(id);
    const tabs = [byId("helpdesk-tab-inbox"), byId("helpdesk-tab-faq")];
    const panels = [byId("helpdesk-panel-inbox"), byId("helpdesk-panel-faq")];
    const feedbackState = byId("helpdesk-feedback-state");
    const feedbackList = byId("helpdesk-feedback-list");
    const feedbackFilter = byId("helpdesk-feedback-filter");
    const faqState = byId("helpdesk-faq-state");
    const faqList = byId("helpdesk-faq-list");
    const faqCreateForm = byId("helpdesk-faq-create");
    const faqCreateState = byId("helpdesk-faq-create-state");
    const faqQuestion = byId("helpdesk-faq-new-question");
    const faqAnswer = byId("helpdesk-faq-new-answer");
    const overview = byId("helpdesk-overview");
    const feedbackFilterButtons = Array.from(
        feedbackFilter.querySelectorAll("button[data-status]")
    );
    const feedbackTypes = {
        wrong_verdict: "Wrong verdict",
        suggestion: "Suggestion",
        bug: "Bug",
    };
    let activeFeedbackStatus = "all";
    let faqLoaded = false;
    const feedbackStatusLabels = {
        all: "All",
        new: "New",
        reviewed: "Reviewed",
        resolved: "Resolved",
    };

    if (!tabs[0] || !tabs[1] || !feedbackList || !faqList || !overview) return;

    function node(tag, className, text) {
        const item = document.createElement(tag);
        if (className) item.className = className;
        if (text !== undefined && text !== null) item.textContent = String(text);
        return item;
    }

    function setState(target, message, kind) {
        target.replaceChildren();
        target.dataset.state = kind || "";
        target.textContent = message || "";
    }

    function setError(target, error, retry) {
        target.replaceChildren();
        target.dataset.state = "error";
        const message = node("span", "", `Error: ${error.message}`);
        target.append(message);
        if (retry) {
            const button = node("button", "", "Retry");
            button.type = "button";
            button.addEventListener("click", retry);
            target.append(button);
        }
    }

    async function api(path, options) {
        if (!window.SOCPOWAuth || typeof window.SOCPOWAuth.fetch !== "function") {
            throw new Error("Authentication helper is unavailable. Reload the page and try again.");
        }
        const response = await window.SOCPOWAuth.fetch(path, options);
        let data = {};
        try {
            data = await response.json();
        } catch (_error) {
            data = {};
        }
        if (!response.ok) {
            throw new Error(typeof data.detail === "string" ? data.detail : `Request failed (${response.status})`);
        }
        return data;
    }

    function jsonOptions(method, payload) {
        return {
            method,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        };
    }

    function showUnavailableSummary() {
        ["all", "new", "reviewed", "resolved"].forEach((status) => {
            const count = byId(`helpdesk-count-${status}`);
            if (count) count.textContent = "· –";
            const button = feedbackFilterButtons.find((item) => item.dataset.status === status);
            if (button) button.setAttribute("aria-label", `${feedbackStatusLabels[status]}, –`);
        });
        const inboxCount = byId("helpdesk-tab-inbox-count");
        inboxCount.textContent = "– new";
        inboxCount.hidden = false;
        byId("helpdesk-tab-inbox").setAttribute("aria-label", "Inbox, – new");
        byId("helpdesk-tab-faq-count").textContent = "–";
        byId("helpdesk-tab-faq").setAttribute("aria-label", "FAQ editor, –");
        ["new", "reviewed", "resolved", "published", "unpublished"].forEach((key) => {
            byId(`helpdesk-overview-${key}`).textContent = "–";
        });
    }

    function renderSummary(data) {
        const feedback = data.feedback || {};
        const faq = data.faq || {};
        const newCount = Number(feedback.new) || 0;
        const faqTotal = Number(faq.total) || 0;
        const values = {
            all: feedback.total,
            new: feedback.new,
            reviewed: feedback.reviewed,
            resolved: feedback.resolved,
        };
        Object.entries(values).forEach(([status, value]) => {
            const count = Number.isFinite(Number(value)) ? Number(value) : 0;
            byId(`helpdesk-count-${status}`).textContent = `· ${count}`;
            const button = feedbackFilterButtons.find((item) => item.dataset.status === status);
            if (button) button.setAttribute("aria-label", `${feedbackStatusLabels[status]}, ${count}`);
        });
        const inboxCount = byId("helpdesk-tab-inbox-count");
        inboxCount.textContent = `${newCount} new`;
        inboxCount.hidden = newCount === 0;
        byId("helpdesk-tab-inbox").setAttribute(
            "aria-label",
            newCount > 0 ? `Inbox, ${newCount} new` : "Inbox",
        );
        byId("helpdesk-tab-faq-count").textContent = String(faqTotal);
        byId("helpdesk-tab-faq").setAttribute("aria-label", `FAQ editor, ${faqTotal}`);
        byId("helpdesk-overview-new").textContent = String(Number(feedback.new) || 0);
        byId("helpdesk-overview-reviewed").textContent = String(Number(feedback.reviewed) || 0);
        byId("helpdesk-overview-resolved").textContent = String(Number(feedback.resolved) || 0);
        byId("helpdesk-overview-published").textContent = String(Number(faq.published) || 0);
        byId("helpdesk-overview-unpublished").textContent = String(Number(faq.unpublished) || 0);
    }

    async function refreshSummary() {
        try {
            const data = await api("/api/helpdesk/admin/summary");
            renderSummary(data);
        } catch (_error) {
            showUnavailableSummary();
        }
    }

    function addLabeledControl(parent, title, control, id) {
        const label = node("label", "", title);
        label.htmlFor = id;
        parent.append(label, control);
    }

    function updateCounter(control, counter, maximum) {
        counter.textContent = `${control.value.length} / ${maximum}`;
    }

    function addCounter(control, counter, maximum) {
        control.addEventListener("input", () => updateCounter(control, counter, maximum));
        updateCounter(control, counter, maximum);
    }

    function activateTab(index, focusTab) {
        tabs.forEach((tab, position) => {
            const selected = position === index;
            tab.setAttribute("aria-selected", String(selected));
            tab.tabIndex = selected ? 0 : -1;
            panels[position].hidden = !selected;
        });
        if (focusTab) tabs[index].focus();
        if (index === 1 && !faqLoaded) loadFaq();
    }

    tabs.forEach((tab, index) => {
        tab.addEventListener("click", () => activateTab(index, false));
        tab.addEventListener("keydown", (event) => {
            let next = null;
            if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
            if (event.key === "ArrowLeft") next = (index + tabs.length - 1) % tabs.length;
            if (event.key === "Home") next = 0;
            if (event.key === "End") next = tabs.length - 1;
            if (next !== null) {
                event.preventDefault();
                activateTab(next, true);
            }
        });
    });

    function formatCreatedAt(rawValue) {
        if (!rawValue) return "Unknown";
        const isoValue = rawValue.includes("T")
            ? rawValue
            : `${rawValue.replace(" ", "T")}Z`;
        const parsed = new Date(isoValue);
        return Number.isNaN(parsed.getTime()) ? rawValue : parsed.toLocaleString();
    }

    async function loadFeedback(selectedStatus = activeFeedbackStatus) {
        activeFeedbackStatus = selectedStatus;
        feedbackFilterButtons.forEach((button) => {
            button.setAttribute("aria-pressed", String(button.dataset.status === selectedStatus));
        });
        setState(feedbackState, "Loading feedback…", "loading");
        feedbackList.replaceChildren();
        const suffix = selectedStatus === "all" ? "" : `?status=${encodeURIComponent(selectedStatus)}`;
        try {
            const data = await api(`/api/helpdesk/admin/feedback${suffix}`);
            const items = Array.isArray(data.items) ? data.items : [];
            if (!items.length) {
                setState(
                    feedbackState,
                    selectedStatus === "all"
                        ? "No feedback yet. Reports submitted from Ask the SOC Room will appear here."
                        : "No feedback matches this filter.",
                    "empty",
                );
                return;
            }
            setState(feedbackState, `${items.length} feedback item${items.length === 1 ? "" : "s"}.`, "loaded");
            items.forEach((item) => feedbackList.append(renderFeedback(item)));
        } catch (error) {
            setError(feedbackState, error, loadFeedback);
        }
    }

    function renderFeedback(item) {
        const card = node("article", "helpdesk-admin-card helpdesk-feedback-card");
        const knownType = Object.prototype.hasOwnProperty.call(feedbackTypes, item.type);
        card.dataset.type = knownType ? item.type : "unknown";
        const heading = node("div", "helpdesk-admin-card-heading");
        heading.append(node("h3", "", `Feedback #${item.id}`));
        const badges = node("div", "helpdesk-feedback-badges");
        const typeBadge = node(
            "span",
            "helpdesk-type-badge",
            knownType ? feedbackTypes[item.type] : String(item.type || "Feedback"),
        );
        typeBadge.dataset.type = knownType ? item.type : "unknown";
        badges.append(typeBadge);
        const reference = node(
            "span",
            "helpdesk-reference-chip",
            `Reference: ${item.reference || "None"}`,
        );
        badges.append(reference);
        const meta = node("div", "helpdesk-feedback-meta");
        meta.append(node("span", "", `Created: ${formatCreatedAt(item.created_at)}`));
        card.append(
            heading,
            badges,
            meta,
            node("p", "helpdesk-feedback-message", item.message || ""),
        );

        const form = node("form", "helpdesk-feedback-editor");
        const status = node("select");
        status.id = `feedback-status-${item.id}`;
        [["new", "New"], ["reviewed", "Reviewed"], ["resolved", "Resolved"]].forEach(([value, label]) => {
            const option = node("option", "", label);
            option.value = value;
            status.append(option);
        });
        status.value = item.status;
        const statusWrap = node("div", "helpdesk-admin-field");
        addLabeledControl(statusWrap, "Status", status, status.id);

        const note = node("textarea");
        note.id = `feedback-note-${item.id}`;
        note.maxLength = 2000;
        note.rows = 3;
        note.value = item.admin_note || "";
        const noteWrap = node("div", "helpdesk-admin-field");
        addLabeledControl(noteWrap, "Add admin note", note, note.id);
        const counter = node("p", "helpdesk-admin-counter");
        addCounter(note, counter, 2000);
        noteWrap.append(counter);

        const footer = node("div", "helpdesk-feedback-footer");
        footer.append(
            node("span", "helpdesk-feedback-submitter", `Submitted by ${item.submitter_username || "Unknown user"}`),
            statusWrap,
            noteWrap,
        );
        const actions = node("div", "helpdesk-admin-actions helpdesk-feedback-actions");
        const save = node("button", "helpdesk-admin-button--primary", "Save");
        save.type = "submit";
        actions.append(save);
        const createFaq = node(
            "button",
            "helpdesk-admin-button helpdesk-admin-button--outline",
            "Create FAQ from this",
        );
        createFaq.type = "button";
        createFaq.addEventListener("click", () => {
            activateTab(1, false);
            faqQuestion.value = (item.message || "").slice(0, 300);
            updateCounter(faqQuestion, byId("helpdesk-faq-new-question-count"), 300);
            faqQuestion.focus();
        });
        actions.append(createFaq);
        footer.append(actions);
        form.append(footer);
        const state = node("div", "helpdesk-admin-state");
        state.setAttribute("role", "status");
        state.setAttribute("aria-live", "polite");
        form.append(state);
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            save.disabled = true;
            setState(state, "Saving…", "saving");
            try {
                await api(`/api/helpdesk/admin/feedback/${item.id}`, jsonOptions("PATCH", {
                    status: status.value,
                    admin_note: note.value,
                }));
                item.status = status.value;
                item.admin_note = note.value;
                setState(state, "Saved.", "saved");
                await refreshSummary();
            } catch (error) {
                setState(state, `Save error: ${error.message}`, "error");
            } finally {
                save.disabled = false;
            }
        });
        card.append(form);
        return card;
    }

    async function loadFaq() {
        setState(faqState, "Loading FAQ entries…", "loading");
        faqList.replaceChildren();
        try {
            const data = await api("/api/helpdesk/admin/faq");
            const items = Array.isArray(data.items) ? data.items : [];
            faqLoaded = true;
            if (!items.length) {
                setState(
                    faqState,
                    "No FAQ entries yet. Use 'Create FAQ from this' on a report, or add one here.",
                    "empty",
                );
                return;
            }
            setState(faqState, `${items.length} FAQ entr${items.length === 1 ? "y" : "ies"}.`, "loaded");
            items.forEach((item) => faqList.append(renderFaq(item)));
        } catch (error) {
            faqLoaded = false;
            setError(faqState, error, loadFaq);
        }
    }

    function renderFaq(item) {
        const card = node("article", "helpdesk-admin-card helpdesk-faq-card");
        const heading = node("div", "helpdesk-admin-card-heading");
        const title = node("h3", "", item.question || "FAQ entry");
        const summary = node("p", "helpdesk-feedback-meta", `Sort order: ${item.sort_order} · ${item.is_published ? "Published" : "Unpublished"}`);
        heading.append(title, summary);
        card.append(heading);

        const form = node("form", "helpdesk-admin-edit-grid");
        const question = node("textarea");
        question.id = `faq-question-${item.id}`;
        question.maxLength = 300;
        question.rows = 2;
        question.required = true;
        question.value = item.question || "";
        const questionWrap = node("div", "helpdesk-admin-field");
        addLabeledControl(questionWrap, "Question", question, question.id);
        const questionCount = node("p", "helpdesk-admin-counter");
        addCounter(question, questionCount, 300);
        questionWrap.append(questionCount);

        const answer = node("textarea");
        answer.id = `faq-answer-${item.id}`;
        answer.maxLength = 4000;
        answer.rows = 4;
        answer.required = true;
        answer.value = item.answer || "";
        const answerWrap = node("div", "helpdesk-admin-field");
        addLabeledControl(answerWrap, "Answer", answer, answer.id);
        const answerCount = node("p", "helpdesk-admin-counter");
        addCounter(answer, answerCount, 4000);
        answerWrap.append(answerCount);
        form.append(questionWrap, answerWrap);

        const sortOrder = node("input");
        sortOrder.type = "number";
        sortOrder.id = `faq-sort-${item.id}`;
        sortOrder.value = String(item.sort_order ?? 0);
        const sortWrap = node("div", "helpdesk-admin-field");
        addLabeledControl(sortWrap, "Sort order", sortOrder, sortOrder.id);

        const published = node("input");
        published.type = "checkbox";
        published.id = `faq-published-${item.id}`;
        published.checked = Number(item.is_published) === 1;
        const publishedLabel = node("label", "helpdesk-admin-checkbox", "Published");
        publishedLabel.htmlFor = published.id;
        publishedLabel.prepend(published);
        const fields = node("div", "helpdesk-admin-edit-grid");
        fields.append(sortWrap, publishedLabel);
        form.append(fields);

        const state = node("div", "helpdesk-admin-state");
        state.setAttribute("role", "status");
        state.setAttribute("aria-live", "polite");
        const actions = node("div", "helpdesk-admin-actions helpdesk-faq-actions");
        const save = node("button", "helpdesk-admin-button--primary", "Save changes");
        save.type = "submit";
        const remove = node("button", "helpdesk-admin-button--danger", "Delete");
        remove.type = "button";
        actions.append(save, remove);
        form.append(actions, state);

        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            save.disabled = true;
            setState(state, "Saving…", "saving");
            const changes = {
                question: question.value,
                answer: answer.value,
                sort_order: Number(sortOrder.value || 0),
                is_published: published.checked ? 1 : 0,
            };
            try {
                await api(`/api/helpdesk/admin/faq/${item.id}`, jsonOptions("PATCH", changes));
                Object.assign(item, changes);
                title.textContent = item.question;
                summary.textContent = `Sort order: ${item.sort_order} · ${item.is_published ? "Published" : "Unpublished"}`;
                setState(state, "Saved.", "saved");
                await refreshSummary();
            } catch (error) {
                setState(state, `Save error: ${error.message}`, "error");
            } finally {
                save.disabled = false;
            }
        });

        remove.addEventListener("click", async () => {
            if (remove.dataset.confirming !== "true") {
                remove.dataset.confirming = "true";
                remove.textContent = "Confirm delete";
                const cancel = node("button", "", "Cancel");
                cancel.type = "button";
                cancel.addEventListener("click", () => {
                    remove.dataset.confirming = "false";
                    remove.textContent = "Delete";
                    cancel.remove();
                    setState(state, "", "");
                });
                actions.append(cancel);
                setState(state, "Confirm that you want to delete this FAQ entry.", "confirm");
                return;
            }
            remove.disabled = true;
            setState(state, "Deleting…", "saving");
            try {
                await api(`/api/helpdesk/admin/faq/${item.id}`, { method: "DELETE" });
                card.remove();
                const remaining = faqList.children.length;
                setState(
                    faqState,
                    remaining
                        ? `${remaining} FAQ entries.`
                        : "No FAQ entries yet. Use 'Create FAQ from this' on a report, or add one here.",
                    remaining ? "loaded" : "empty",
                );
                await refreshSummary();
            } catch (error) {
                setState(state, `Delete error: ${error.message}`, "error");
                remove.disabled = false;
            }
        });
        card.append(form);
        return card;
    }

    faqCreateForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const submit = faqCreateForm.querySelector('button[type="submit"]');
        submit.disabled = true;
        setState(faqCreateState, "Saving FAQ…", "saving");
        try {
            await api("/api/helpdesk/admin/faq", jsonOptions("POST", {
                question: faqQuestion.value,
                answer: faqAnswer.value,
                sort_order: Number(byId("helpdesk-faq-new-sort").value || 0),
                is_published: byId("helpdesk-faq-new-published").checked ? 1 : 0,
            }));
            faqCreateForm.reset();
            updateCounter(faqQuestion, byId("helpdesk-faq-new-question-count"), 300);
            updateCounter(faqAnswer, byId("helpdesk-faq-new-answer-count"), 4000);
            faqLoaded = false;
            await loadFaq();
            setState(faqCreateState, "Saved.", "saved");
            await refreshSummary();
        } catch (error) {
            setState(faqCreateState, `Save error: ${error.message}`, "error");
        } finally {
            submit.disabled = false;
        }
    });

    feedbackFilterButtons.forEach((button) => {
        button.addEventListener("click", () => loadFeedback(button.dataset.status));
    });
    addCounter(faqQuestion, byId("helpdesk-faq-new-question-count"), 300);
    addCounter(faqAnswer, byId("helpdesk-faq-new-answer-count"), 4000);
    showUnavailableSummary();
    refreshSummary();
    loadFeedback();
})();
