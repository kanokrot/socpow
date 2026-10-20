(() => {
    "use strict";

    const brand = document.querySelector(".soc-operations-page")?.dataset.brand || "SOCPOW";

    const shell = document.getElementById("soc-room-shell");
    const canvas = document.getElementById("soc-office-canvas");
    const badge = document.getElementById("soc-status-badge");
    const monitor = shell?.querySelector(".soc-monitor-card");
    const activityPanel = document.querySelector(".soc-activity-panel");
    const caseCard = activityPanel?.querySelector(".soc-case-card");

    if (!shell || !canvas || !badge || !monitor) return;

    const CAMERA = {
        idle: { scale: 1, x: "50%", y: "50%", label: "OVERVIEW" },
        queued: { scale: 1.10, x: "52%", y: "63%", label: "TEAM DISPATCH" },
        enrichment: { scale: 1.42, x: "24%", y: "29%", label: "ANALYST NOVA" },
        correlation: { scale: 1.34, x: "47%", y: "44%", label: "SERVER CORRELATION" },
        scoring: { scale: 1.38, x: "66%", y: "31%", label: "ANALYST BYTE" },
        classification: { scale: 1.24, x: "50%", y: "34%", label: "THREAT RESPONSE" },
        reporting: { scale: 1.34, x: "76%", y: "64%", label: "REPORT STATION" },
        completed: { scale: 1, x: "50%", y: "50%", label: "MISSION COMPLETE" },
    };

    const DEFAULT_SCENARIO = {
        id: "malicious", ioc: "44.238.29.244", caseId: "CASE-1024",
        verdict: "MALICIOUS", severity: "HIGH", score: 87, glitch: true,
    };

    function getScenario() {
        return window.SOC_GET_ACTIVE_SCENARIO ? window.SOC_GET_ACTIVE_SCENARIO() : DEFAULT_SCENARIO;
    }

    function buildRisk(scenario) {
        return {
            idle: 0,
            queued: Math.max(4, Math.round(scenario.score * 0.07)),
            enrichment: Math.round(scenario.score * 0.4),
            correlation: Math.round(scenario.score * 0.7),
            scoring: scenario.score,
            classification: scenario.score,
            reporting: scenario.score,
            completed: scenario.score,
        };
    }

    function buildSpeech(scenario) {
        const isClean = scenario.verdict === "CLEAN";
        const isSuspicious = scenario.verdict === "SUSPICIOUS";
        return {
            idle: [],
            queued: [
                { name: "NOVA", text: "New IOC received!", x: "48%", y: "57%" },
                { name: "BYTE", text: "Moving to station.", x: "76%", y: "61%" },
            ],
            enrichment: [
                { name: "NOVA", text: "Querying 9 intel sources...", x: "27%", y: "30%" },
                { name: "BYTE", text: "Checking reputation.", x: "52%", y: "31%" },
            ],
            correlation: isClean
                ? [
                    { name: "NOVA", text: "No related activity found.", x: "47%", y: "39%" },
                    { name: "BYTE", text: "Nothing to link.", x: "32%", y: "29%" },
                ]
                : [
                    { name: "NOVA", text: "Related campaign found!", x: "47%", y: "39%" },
                    { name: "BYTE", text: "Linking evidence now.", x: "32%", y: "29%" },
                ],
            scoring: [
                { name: "NOVA", text: "Calculating risk score...", x: "30%", y: "29%" },
                { name: "BYTE", text: `Risk score: ${scenario.score}`, x: "67%", y: "30%" },
            ],
            classification: isClean
                ? [
                    { name: "NOVA", text: "Looks clean.", x: "32%", y: "28%" },
                    { name: "BYTE", text: "Closing as CLEAN.", x: "68%", y: "30%" },
                ]
                : isSuspicious
                ? [
                    { name: "NOVA", text: "SUSPICIOUS activity.", x: "32%", y: "28%" },
                    { name: "BYTE", text: "Flagging for review.", x: "68%", y: "30%" },
                ]
                : [
                    { name: "NOVA", text: "HIGH THREAT!", x: "32%", y: "28%" },
                    { name: "BYTE", text: "Escalating severity.", x: "68%", y: "30%" },
                ],
            reporting: [
                { name: "NOVA", text: "Writing findings...", x: "30%", y: "30%" },
                { name: "BYTE", text: "Report almost ready.", x: "74%", y: "59%" },
            ],
            completed: [
                { name: "NOVA", text: "Analysis complete ✓", x: "43%", y: "51%" },
                { name: "BYTE", text: "Report generated ✓", x: "72%", y: "57%" },
            ],
        };
    }

    function buildTerminal(scenario) {
        const isClean = scenario.verdict === "CLEAN";
        const classificationLines = [
            {
                type: scenario.glitch ? "danger" : scenario.verdict === "SUSPICIOUS" ? "warning" : "success",
                text: `[verdict] ${scenario.verdict} severity=${scenario.severity}`,
            },
            {
                type: "muted",
                text: isClean ? "[ticket] creating audit record..." : "[ticket] creating incident ticket...",
            },
        ];
        if (!isClean) {
            classificationLines.push({
                type: scenario.glitch ? "danger" : "warning",
                text: "[notification] alert dispatched to analyst",
            });
        }

        return {
            idle: [
                { type: "muted", text: `[system] ${brand} terminal ready` },
                { type: "muted", text: "[system] waiting for IOC event..." },
            ],
            queued: [
                { type: "command", text: `$ investigate_ioc ${scenario.ioc}` },
                { type: "muted", text: "[queue] analysis_id=AN-8821" },
            ],
            enrichment: [
                { type: "command", text: `$ investigate_ioc ${scenario.ioc}` },
                { type: "success", text: "[intel] 9 sources responded" },
            ],
            correlation: isClean
                ? [
                    { type: "command", text: "$ correlate_findings" },
                    { type: "muted", text: "[match] no related campaign found" },
                ]
                : [
                    { type: "command", text: "$ correlate_findings" },
                    { type: "warning", text: "[match] related TTPs found" },
                ],
            scoring: [
                { type: "command", text: "$ calculate_ioc_score" },
                { type: isClean ? "success" : "warning", text: `[score] risk=${scenario.score}` },
            ],
            classification: classificationLines,
            reporting: [
                { type: "command", text: "$ generate_ioc_report" },
                { type: "muted", text: "[report] rendering HTML report..." },
            ],
            completed: [
                { type: "success", text: "[done] ioc_report.html generated" },
                { type: "success", text: "[done] analysis completed in 27.4s" },
            ],
        };
    }

    const terminalState = {
        output: null,
        caseLabel: null,
        queue: [],
        active: null,
        activeElement: null,
        index: 0,
        accumulator: 0,
    };

    const riskState = { current: 0, target: 0, value: null, ring: null, card: null, level: null, confidence: null };
    const speechBubbles = [];
    let networkMap = null;
    let cameraLabel = null;
    let currentStage = "idle";
    let lastFrame = performance.now();

    function injectAdvancedUI() {
        injectCameraIndicator();
        injectNetworkMap();
        injectTerminal();
        injectRiskScore();
        injectSpeechLayer();
        injectGlitchOverlay();
    }

    function injectCameraIndicator() {
        const indicator = document.createElement("div");
        indicator.className = "soc-camera-indicator";
        indicator.innerHTML = '<span class="soc-camera-reticle">⌖</span><span>CAM: </span><span class="soc-camera-label">OVERVIEW</span>';
        cameraLabel = indicator.querySelector(".soc-camera-label");
        shell.appendChild(indicator);
    }

    function injectNetworkMap() {
        networkMap = document.createElement("div");
        networkMap.className = "soc-network-map";
        networkMap.dataset.stage = "idle";
        networkMap.setAttribute("aria-label", "Mini network map");
        networkMap.innerHTML = `
            <div class="soc-overlay-title">NETWORK MAP</div>
            <svg viewBox="0 0 220 104" role="img" aria-label="${brand} analysis network flow">
                <path class="soc-net-link link-input" d="M28 52 H80" />
                <path class="soc-net-link link-intel" d="M110 42 L160 19" />
                <path class="soc-net-link link-server" d="M110 61 L160 83" />
                <path class="soc-net-link link-report" d="M184 25 V77" />
                <g class="soc-net-node node-ioc" transform="translate(8 39)"><rect width="40" height="25" rx="3"/><text x="20" y="15">IOC</text></g>
                <g class="soc-net-node node-socpow" transform="translate(80 34)"><rect width="42" height="36" rx="3"/><text x="21" y="21">${brand.toUpperCase()}</text></g>
                <g class="soc-net-node node-intel" transform="translate(158 7)"><rect width="52" height="24" rx="3"/><text x="26" y="15">INTEL</text></g>
                <g class="soc-net-node node-server" transform="translate(158 73)"><rect width="52" height="24" rx="3"/><text x="26" y="15">SERVER</text></g>
            </svg>`;
        shell.appendChild(networkMap);
    }

    function injectTerminal() {
        monitor.classList.add("soc-terminal-card");
        const legacyStage = document.getElementById("soc-monitor-stage");
        const legacyCase = document.getElementById("soc-monitor-case");
        const legacyWrap = document.createElement("div");
        legacyWrap.className = "soc-terminal-legacy-hidden";
        legacyWrap.style.display = "none";
        if (legacyStage) legacyWrap.appendChild(legacyStage);
        if (legacyCase) legacyWrap.appendChild(legacyCase);
        monitor.replaceChildren();

        const head = document.createElement("div");
        head.className = "soc-terminal-head";
        head.innerHTML = `
            <span class="soc-terminal-lights"><i></i><i></i><i></i></span>
            <strong>${brand.toUpperCase()} SOC TERMINAL</strong>
            <small>CASE-1024</small>`;
        terminalState.caseLabel = head.querySelector("small");

        const output = document.createElement("div");
        output.className = "soc-terminal-output";
        output.setAttribute("aria-label", "Live terminal output");
        terminalState.output = output;

        const prompt = document.createElement("div");
        prompt.className = "soc-terminal-prompt";
        prompt.innerHTML = `<span>${brand.toLowerCase()}@soc:~$</span><i class="soc-terminal-cursor"></i>`;

        monitor.append(head, output, prompt, legacyWrap);
    }

    function injectRiskScore() {
        if (!activityPanel || !caseCard) return;
        const card = document.createElement("div");
        card.className = "soc-risk-card";
        card.dataset.level = "pending";
        card.innerHTML = `
            <div class="soc-risk-ring" style="--risk: 0">
                <div><strong class="soc-risk-value">0</strong><small>/100</small></div>
            </div>
            <div class="soc-risk-copy">
                <span>RISK SCORE</span>
                <strong class="soc-risk-level">PENDING</strong>
                <small class="soc-risk-confidence">confidence 0%</small>
            </div>`;
        caseCard.insertAdjacentElement("afterend", card);
        riskState.card = card;
        riskState.ring = card.querySelector(".soc-risk-ring");
        riskState.value = card.querySelector(".soc-risk-value");
        riskState.level = card.querySelector(".soc-risk-level");
        riskState.confidence = card.querySelector(".soc-risk-confidence");
    }

    function injectSpeechLayer() {
        const layer = document.createElement("div");
        layer.className = "soc-speech-layer";
        layer.setAttribute("aria-live", "polite");
        for (let i = 0; i < 2; i += 1) {
            const bubble = document.createElement("div");
            bubble.className = "soc-speech-bubble";
            bubble.innerHTML = '<span class="soc-speech-name"></span><span class="soc-speech-text"></span>';
            layer.appendChild(bubble);
            speechBubbles.push(bubble);
        }
        shell.appendChild(layer);
    }

    function injectGlitchOverlay() {
        const overlay = document.createElement("div");
        overlay.className = "soc-glitch-overlay";
        overlay.setAttribute("aria-hidden", "true");
        shell.appendChild(overlay);
    }

    let speechTimer = null;

    function applyStage(stage) {
        currentStage = CAMERA[stage] ? stage : "idle";
        const scenario = getScenario();

        applyCamera(currentStage);
        applyRisk(currentStage, scenario);
        if (terminalState.caseLabel) terminalState.caseLabel.textContent = scenario.caseId;

        speechBubbles.forEach((bubble) => bubble.classList.remove("is-visible"));
        clearTimeout(speechTimer);
        speechTimer = setTimeout(() => applySpeech(currentStage, scenario), 1100);

        queueTerminal(buildTerminal(scenario)[currentStage] || []);
        if (networkMap) networkMap.dataset.stage = currentStage;
        shell.classList.toggle("soc-advanced-glitch", currentStage === "classification" && scenario.glitch);
    }

    function applyCamera(stage) {
        const camera = CAMERA[stage];
        canvas.style.setProperty("--adv-scale", camera.scale);
        canvas.style.setProperty("--adv-origin-x", camera.x);
        canvas.style.setProperty("--adv-origin-y", camera.y);
        if (cameraLabel) cameraLabel.textContent = camera.label;
    }

    function applyRisk(stage, scenario) {
        riskState.target = buildRisk(scenario)[stage] ?? 0;
    }

    function applySpeech(stage, scenario) {
        const camera = CAMERA[stage] || CAMERA.idle;
        const scale = camera.scale;
        const ox = parseFloat(camera.x) / 100;
        const oy = parseFloat(camera.y) / 100;

        const messages = buildSpeech(scenario)[stage] || [];
        speechBubbles.forEach((bubble, index) => {
            const message = messages[index];
            if (!message) {
                bubble.classList.remove("is-visible");
                return;
            }

            const u = parseFloat(message.x) / 100;
            const v = parseFloat(message.y) / 100;
            const screenX = (ox + (u - ox) * scale) * 100;
            const screenY = (oy + (v - oy) * scale) * 100;

            bubble.style.setProperty("--bubble-x", `${screenX}%`);
            bubble.style.setProperty("--bubble-y", `${screenY}%`);
            bubble.querySelector(".soc-speech-name").textContent = message.name;
            bubble.querySelector(".soc-speech-text").textContent = message.text;
            bubble.classList.add("is-visible");
        });
    }

    function queueTerminal(lines) {
        if (currentStage === "idle" && terminalState.output) {
            terminalState.output.replaceChildren();
            terminalState.queue = [];
            terminalState.active = null;
            terminalState.activeElement = null;
        }
        terminalState.queue.push(...lines);
    }

    function updateTerminal(dt) {
        if (!terminalState.output) return;
        if (!terminalState.active && terminalState.queue.length) {
            terminalState.active = terminalState.queue.shift();
            terminalState.activeElement = document.createElement("div");
            terminalState.activeElement.className = `soc-terminal-line is-${terminalState.active.type}`;
            terminalState.output.appendChild(terminalState.activeElement);
            terminalState.index = 0;
            terminalState.accumulator = 0;
        }
        if (!terminalState.active || !terminalState.activeElement) return;

        terminalState.accumulator += dt * 48;
        const count = Math.floor(terminalState.accumulator);
        if (count <= 0) return;
        terminalState.accumulator -= count;
        terminalState.index = Math.min(terminalState.active.text.length, terminalState.index + count);
        terminalState.activeElement.textContent = terminalState.active.text.slice(0, terminalState.index);

        if (terminalState.index >= terminalState.active.text.length) {
            terminalState.active = null;
            terminalState.activeElement = null;
            while (terminalState.output.children.length > 6) {
                terminalState.output.firstElementChild?.remove();
            }
        }
    }

    function updateRisk(dt) {
        const delta = riskState.target - riskState.current;
        if (Math.abs(delta) < 0.05) riskState.current = riskState.target;
        else riskState.current += delta * Math.min(1, dt * 2.2);

        if (!riskState.ring || !riskState.value || !riskState.card) return;
        const value = Math.round(riskState.current);
        const level = value >= 90 ? "critical" : value >= 70 ? "high" : value >= 40 ? "medium" : value > 0 ? "low" : "pending";
        const label = level === "critical" ? "CRITICAL" : level.toUpperCase();
        const confidence = value === 0 ? 0 : Math.min(96, Math.round(50 + value * 0.47));
        riskState.ring.style.setProperty("--risk", value);
        riskState.value.textContent = String(value);
        riskState.card.dataset.level = level;
        if (riskState.level) riskState.level.textContent = label;
        if (riskState.confidence) riskState.confidence.textContent = `confidence ${confidence}%`;
    }

    function readStage() {
        return badge.dataset.state || "idle";
    }

    function loop(now) {
        const dt = Math.min(0.1, Math.max(0, (now - lastFrame) / 1000));
        lastFrame = now;
        updateTerminal(dt);
        updateRisk(dt);
        requestAnimationFrame(loop);
    }

    injectAdvancedUI();
    applyStage(readStage());

    const observer = new MutationObserver(() => {
        const nextStage = readStage();
        if (nextStage !== currentStage) applyStage(nextStage);
    });
    observer.observe(badge, { attributes: true, attributeFilter: ["data-state"] });

    requestAnimationFrame((now) => {
        lastFrame = now;
        requestAnimationFrame(loop);
    });
})();
