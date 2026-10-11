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
    let faqLoaded = false;

    if (!tabs[0] || !tabs[1] || !feedbackList || !faqList) return;

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
        if (!window.CABTAAuth || typeof window.CABTAAuth.fetch !== "function") {
            throw new Error("Authentication helper is unavailable. Reload the page and try again.");
        }
        const response = await window.CABTAAuth.fetch(path, options);
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

    async function loadFeedback() {
        setState(feedbackState, "Loading feedback…", "loading");
        feedbackList.replaceChildren();
        const selectedStatus = feedbackFilter.value;
        const suffix = selectedStatus === "all" ? "" : `?status=${encodeURIComponent(selectedStatus)}`;
        try {
            const data = await api(`/api/helpdesk/admin/feedback${suffix}`);
            const items = Array.isArray(data.items) ? data.items : [];
            if (!items.length) {
                setState(feedbackState, "No feedback matches this filter.", "empty");
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
        const heading = node("div", "helpdesk-admin-card-heading");
        heading.append(node("h3", "", item.type || "Feedback"));
        const meta = node("div", "helpdesk-feedback-meta");
        meta.append(
            node("span", "", `Reference: ${item.reference || "None"}`),
            node("span", "", `Submitted by: ${item.submitter_username || "Unknown user"}`),
            node("span", "", `Created: ${item.created_at || "Unknown"}`),
        );
        card.append(heading, meta, node("p", "helpdesk-feedback-message", item.message || ""));

        const form = node("form", "helpdesk-admin-edit-grid");
        const status = node("select");
        status.id = `feedback-status-${item.id}`;
        [["new", "New"], ["reviewed", "Reviewed"], ["resolved", "Resolved"]].forEach(([value, label]) => {
            const option = node("option", "", label);
            option.value = value;
            status.append(option);
        });
        status.value = item.status;
        addLabeledControl(form, "Status", status, status.id);

        const note = node("textarea");
        note.id = `feedback-note-${item.id}`;
        note.maxLength = 2000;
        note.rows = 3;
        note.value = item.admin_note || "";
        const noteWrap = node("div", "helpdesk-admin-field");
        addLabeledControl(noteWrap, "Admin note", note, note.id);
        const counter = node("p", "helpdesk-admin-counter");
        addCounter(note, counter, 2000);
        noteWrap.append(counter);
        form.append(noteWrap);

        const actions = node("div", "helpdesk-admin-actions helpdesk-feedback-actions");
        const save = node("button", "", "Save");
        save.type = "submit";
        actions.append(save);
        const createFaq = node("button", "", "Create FAQ from this");
        createFaq.type = "button";
        createFaq.addEventListener("click", () => {
            activateTab(1, false);
            faqQuestion.value = (item.message || "").slice(0, 300);
            updateCounter(faqQuestion, byId("helpdesk-faq-new-question-count"), 300);
            faqQuestion.focus();
        });
        actions.append(createFaq);
        form.append(actions);
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
                setState(faqState, "No FAQ entries yet.", "empty");
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
        const save = node("button", "", "Save changes");
        save.type = "submit";
        const remove = node("button", "", "Delete");
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
                setState(faqState, remaining ? `${remaining} FAQ entries.` : "No FAQ entries yet.", remaining ? "loaded" : "empty");
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
        } catch (error) {
            setState(faqCreateState, `Save error: ${error.message}`, "error");
        } finally {
            submit.disabled = false;
        }
    });

    feedbackFilter.addEventListener("change", loadFeedback);
    addCounter(faqQuestion, byId("helpdesk-faq-new-question-count"), 300);
    addCounter(faqAnswer, byId("helpdesk-faq-new-answer-count"), 4000);
    loadFeedback();
})();
