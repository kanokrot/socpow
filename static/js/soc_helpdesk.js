(() => {
    "use strict";

    const panel = document.getElementById("soc-helpdesk-panel");
    const avatar = document.getElementById("soc-helpdesk-avatar");
    const speechText = document.getElementById("soc-helpdesk-speech-text");
    const answersTab = document.getElementById("soc-tab-answers");
    const reportTab = document.getElementById("soc-tab-report");
    const answersPanel = document.getElementById("soc-panel-answers");
    const reportPanel = document.getElementById("soc-panel-report");
    const footer = document.getElementById("soc-helpdesk-footer");
    const faqStatus = document.getElementById("soc-faq-status");
    const faqList = document.getElementById("soc-faq-list");
    const searchInput = document.getElementById("soc-faq-search");
    const categoryChips = document.getElementById("soc-faq-category-chips");
    const emptyState = document.getElementById("soc-faq-empty");
    const emptyText = document.getElementById("soc-faq-empty-text");
    const reportInstead = document.getElementById("soc-faq-report-instead");
    const form = document.getElementById("soc-feedback-form");
    const referenceInput = document.getElementById("soc-feedback-reference");
    const messageInput = document.getElementById("soc-feedback-message");
    const messageCount = document.getElementById("soc-message-count");
    const submitButton = document.getElementById("soc-feedback-submit");
    const feedbackResult = document.getElementById("soc-feedback-result");
    const feedbackSuccess = document.getElementById("soc-feedback-success");
    const sendAnotherButton = document.getElementById("soc-send-another");

    if (!panel || !avatar || !speechText || !answersTab || !reportTab
        || !answersPanel || !reportPanel || !footer || !faqStatus || !faqList
        || !searchInput || !categoryChips || !emptyState || !emptyText
        || !reportInstead || !form || !referenceInput || !messageInput
        || !messageCount || !submitButton || !feedbackResult
        || !feedbackSuccess || !sendAnotherButton) {
        return;
    }

    const speakers = ["NOVA", "BYTE", "ECHO", "LINK"];
    let speakerIndex = 0;
    let faqItems = [];
    let activeCategory = "";
    let openFaqId = null;
    let noMatchState = false;
    let submitting = false;

    function say(text) {
        avatar.textContent = speakers[speakerIndex % speakers.length];
        speakerIndex += 1;
        speechText.textContent = text;
    }

    function messageFromDetail(detail, fallback) {
        if (typeof detail === "string" && detail) return detail;
        if (Array.isArray(detail)) {
            const messages = detail
                .map((item) => (item && typeof item.msg === "string" ? item.msg : ""))
                .filter(Boolean);
            if (messages.length) return messages.join(" ");
        }
        return fallback;
    }

    async function responseData(response) {
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            throw new Error(messageFromDetail(data.detail, `Request failed (${response.status}).`));
        }
        return data;
    }

    function setActiveTab(tabName, announce = true) {
        const isReport = tabName === "report";
        const wasReport = reportTab.getAttribute("aria-selected") === "true";
        answersTab.setAttribute("aria-selected", String(!isReport));
        reportTab.setAttribute("aria-selected", String(isReport));
        answersTab.tabIndex = isReport ? -1 : 0;
        reportTab.tabIndex = isReport ? 0 : -1;
        answersPanel.hidden = isReport;
        reportPanel.hidden = !isReport;
        footer.hidden = !isReport;
        if (announce && wasReport !== isReport) {
            say(isReport
                ? "Tell me what you found..."
                : "Looking for an answer? Search first.");
        }
    }

    answersTab.addEventListener("click", () => setActiveTab("answers"));
    reportTab.addEventListener("click", () => setActiveTab("report"));
    [answersTab, reportTab].forEach((tab) => {
        tab.addEventListener("keydown", (event) => {
            if (event.key !== "ArrowLeft" && event.key !== "ArrowRight"
                && event.key !== "Home" && event.key !== "End") return;
            event.preventDefault();
            const next = event.key === "Home" ? answersTab
                : event.key === "End" ? reportTab
                    : tab === answersTab ? reportTab : answersTab;
            next.focus();
            setActiveTab(next === reportTab ? "report" : "answers");
        });
    });

    function currentMatches() {
        const term = searchInput.value.trim().toLocaleLowerCase();
        return faqItems.filter((item) => {
            const question = typeof item.question === "string" ? item.question : "";
            const answer = typeof item.answer === "string" ? item.answer : "";
            const categoryMatches = !activeCategory || item.category === activeCategory;
            return categoryMatches
                && `${question} ${answer}`.toLocaleLowerCase().includes(term);
        });
    }

    function updateNoMatchSpeech(matches) {
        const hasSearch = searchInput.value.trim().length > 0;
        const isNoMatch = faqItems.length > 0 && hasSearch && matches.length === 0;
        if (isNoMatch !== noMatchState) {
            noMatchState = isNoMatch;
            if (isNoMatch) say("I don't have that one. Send it to the admin...");
        }
    }

    function renderCategoryChips() {
        const categories = [...new Set(faqItems
            .map((item) => typeof item.category === "string" ? item.category.trim() : "")
            .filter(Boolean))];
        categoryChips.replaceChildren();
        categoryChips.hidden = categories.length === 0;
        if (!categories.length) return;

        ["", ...categories].forEach((category) => {
            const chip = document.createElement("button");
            chip.type = "button";
            chip.textContent = category || "All";
            chip.setAttribute("aria-pressed", String(activeCategory === category));
            chip.addEventListener("click", () => {
                activeCategory = category;
                renderCategoryChips();
                renderFaq();
            });
            categoryChips.appendChild(chip);
        });
    }

    function makeFaqItem(item, index) {
        const article = document.createElement("article");
        article.className = "soc-faq-item";

        const id = String(item.id ?? index);
        const question = document.createElement("button");
        question.className = "soc-faq-question";
        question.type = "button";
        question.id = `soc-faq-question-${index}`;
        question.setAttribute("aria-expanded", String(openFaqId === id));
        question.setAttribute("aria-controls", `soc-faq-answer-${index}`);
        question.textContent = typeof item.question === "string" ? item.question : "";

        const answer = document.createElement("div");
        answer.className = "soc-faq-answer";
        answer.id = `soc-faq-answer-${index}`;
        answer.setAttribute("role", "region");
        answer.setAttribute("aria-labelledby", question.id);
        answer.hidden = openFaqId !== id;
        answer.textContent = typeof item.answer === "string" ? item.answer : "";

        question.addEventListener("click", () => {
            const willOpen = openFaqId !== id;
            openFaqId = willOpen ? id : null;
            faqList.querySelectorAll(".soc-faq-question").forEach((button) => {
                const expanded = button === question && willOpen;
                button.setAttribute("aria-expanded", String(expanded));
                document.getElementById(button.getAttribute("aria-controls")).hidden = !expanded;
            });
            if (willOpen) say("Does that answer it?");
        });

        article.append(question, answer);
        return article;
    }

    function renderFaq() {
        const matches = currentMatches();
        updateNoMatchSpeech(matches);
        faqList.replaceChildren();

        if (!faqItems.length) {
            faqStatus.textContent = "";
            emptyText.textContent = "There are no answers yet. You can report a finding instead.";
            emptyState.hidden = false;
            return;
        }

        faqStatus.textContent = "";
        emptyState.hidden = matches.length !== 0;
        emptyText.textContent = "No answers match that search. You can report it instead.";
        matches.forEach((item, index) => faqList.appendChild(makeFaqItem(item, index)));
    }

    function showFaqError(error) {
        faqList.replaceChildren();
        emptyState.hidden = true;
        faqStatus.replaceChildren();
        const text = document.createElement("span");
        text.textContent = `Could not load FAQ. ${error.message}`;
        const retry = document.createElement("button");
        retry.className = "soc-faq-retry";
        retry.type = "button";
        retry.textContent = "Try again";
        retry.addEventListener("click", loadFaq);
        faqStatus.append(text, retry);
    }

    async function loadFaq() {
        faqList.replaceChildren();
        faqStatus.textContent = "Loading FAQ…";
        emptyState.hidden = true;
        try {
            if (!window.SOCPOWAuth || typeof window.SOCPOWAuth.fetch !== "function") {
                throw new Error("Authentication is unavailable. Refresh the page and try again.");
            }
            const response = await window.SOCPOWAuth.fetch("/api/helpdesk/faq");
            const data = await responseData(response);
            faqItems = Array.isArray(data.items) ? data.items : [];
            openFaqId = null;
            activeCategory = "";
            noMatchState = false;
            renderCategoryChips();
            renderFaq();
        } catch (error) {
            showFaqError(error instanceof Error ? error : new Error("Please try again."));
        }
    }

    function updateMessageCount() {
        const validLength = messageInput.value.trim().length >= 5;
        messageCount.textContent = `${messageInput.value.length} / 2000`;
        messageInput.setCustomValidity(validLength ? "" : "Enter at least 5 non-whitespace characters.");
        submitButton.disabled = !validLength || submitting;
    }

    searchInput.addEventListener("input", renderFaq);
    reportInstead.addEventListener("click", () => {
        setActiveTab("report");
        const term = searchInput.value.trim();
        if (!messageInput.value.trim() && term) {
            messageInput.value = `Question: ${term}`;
        }
        updateMessageCount();
        messageInput.focus();
    });

    messageInput.addEventListener("input", updateMessageCount);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (messageInput.value.trim().length < 5) {
            updateMessageCount();
            form.reportValidity();
            return;
        }
        if (!form.reportValidity()) return;

        const selectedType = form.querySelector('input[name="type"]:checked');
        if (!selectedType) return;
        const payload = {
            type: selectedType.value,
            message: messageInput.value,
        };
        if (referenceInput.value !== "") payload.reference = referenceInput.value;

        submitting = true;
        submitButton.textContent = "Sending…";
        updateMessageCount();
        feedbackResult.textContent = "";
        try {
            if (!window.SOCPOWAuth || typeof window.SOCPOWAuth.fetch !== "function") {
                throw new Error("Authentication is unavailable. Refresh the page and try again.");
            }
            const response = await window.SOCPOWAuth.fetch("/api/helpdesk/feedback", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const data = await responseData(response);
            form.reset();
            updateMessageCount();
            form.hidden = true;
            feedbackSuccess.textContent = `Thanks for your report. Reference ID: ${data.id}`;
            feedbackSuccess.hidden = false;
            submitButton.hidden = true;
            sendAnotherButton.hidden = false;
            say("Thanks for helping improve the SOC Room.");
        } catch (error) {
            feedbackResult.textContent = messageFromDetail(
                error instanceof Error ? error.message : "",
                "Could not submit your report. Please try again."
            );
        } finally {
            submitting = false;
            submitButton.textContent = "Send report";
            updateMessageCount();
        }
    });

    sendAnotherButton.addEventListener("click", () => {
        form.reset();
        form.hidden = false;
        feedbackSuccess.hidden = true;
        feedbackSuccess.textContent = "";
        feedbackResult.textContent = "";
        submitButton.hidden = false;
        sendAnotherButton.hidden = true;
        submitButton.textContent = "Send report";
        updateMessageCount();
        messageInput.focus();
    });

    setActiveTab("answers", false);
    updateMessageCount();
    loadFaq();
})();
