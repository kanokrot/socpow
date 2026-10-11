(() => {
    "use strict";

    const faqStatus = document.getElementById("soc-faq-status");
    const faqList = document.getElementById("soc-faq-list");
    const form = document.getElementById("soc-feedback-form");
    const typeInput = document.getElementById("soc-feedback-type");
    const referenceInput = document.getElementById("soc-feedback-reference");
    const messageInput = document.getElementById("soc-feedback-message");
    const messageCount = document.getElementById("soc-message-count");
    const submitButton = document.getElementById("soc-feedback-submit");
    const feedbackResult = document.getElementById("soc-feedback-result");

    if (!faqStatus || !faqList || !form || !typeInput || !referenceInput
        || !messageInput || !messageCount || !submitButton || !feedbackResult) {
        return;
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

    function makeFaqItem(item, index) {
        const article = document.createElement("article");
        article.className = "soc-faq-item";

        const question = document.createElement("button");
        question.className = "soc-faq-question";
        question.type = "button";
        question.id = `soc-faq-question-${index}`;
        question.setAttribute("aria-expanded", "false");
        question.setAttribute("aria-controls", `soc-faq-answer-${index}`);
        question.textContent = typeof item.question === "string" ? item.question : "";

        const answer = document.createElement("div");
        answer.className = "soc-faq-answer";
        answer.id = `soc-faq-answer-${index}`;
        answer.setAttribute("role", "region");
        answer.setAttribute("aria-labelledby", question.id);
        answer.hidden = true;
        answer.textContent = typeof item.answer === "string" ? item.answer : "";

        question.addEventListener("click", () => {
            const expanded = question.getAttribute("aria-expanded") === "true";
            question.setAttribute("aria-expanded", String(!expanded));
            answer.hidden = expanded;
        });

        article.append(question, answer);
        return article;
    }

    function showFaqError(error) {
        faqList.replaceChildren();
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
        try {
            if (!window.CABTAAuth || typeof window.CABTAAuth.fetch !== "function") {
                throw new Error("Authentication is unavailable. Refresh the page and try again.");
            }
            const response = await window.CABTAAuth.fetch("/api/helpdesk/faq");
            const data = await responseData(response);
            const items = Array.isArray(data.items) ? data.items : [];
            if (!items.length) {
                faqStatus.textContent = "No FAQ entries yet";
                return;
            }
            faqStatus.textContent = "";
            items.forEach((item, index) => faqList.appendChild(makeFaqItem(item, index)));
        } catch (error) {
            showFaqError(error instanceof Error ? error : new Error("Please try again."));
        }
    }

    function updateMessageCount() {
        messageCount.textContent = `${messageInput.value.length} / 2000`;
    }

    messageInput.addEventListener("input", updateMessageCount);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!form.reportValidity()) return;

        const payload = {
            type: typeInput.value,
            message: messageInput.value,
        };
        if (referenceInput.value !== "") payload.reference = referenceInput.value;

        submitButton.disabled = true;
        submitButton.textContent = "Sending…";
        feedbackResult.textContent = "";
        try {
            if (!window.CABTAAuth || typeof window.CABTAAuth.fetch !== "function") {
                throw new Error("Authentication is unavailable. Refresh the page and try again.");
            }
            const response = await window.CABTAAuth.fetch("/api/helpdesk/feedback", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const data = await responseData(response);
            feedbackResult.textContent = `Report submitted. Reference ID: ${data.id}`;
            form.reset();
            updateMessageCount();
        } catch (error) {
            feedbackResult.textContent = messageFromDetail(
                error instanceof Error ? error.message : "",
                "Could not submit your report. Please try again."
            );
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = "Send report";
        }
    });

    updateMessageCount();
    loadFaq();
})();
