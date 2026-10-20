(() => {
    "use strict";

    const brand = document.querySelector(".soc-operations-page")?.dataset.brand || "SOCPOW";

    const canvas = document.getElementById("soc-office-canvas");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.imageSmoothingEnabled = false;

    const TILE = 16;
    const ZOOM = 2;
    const LOGICAL_W = canvas.width / ZOOM;
    const LOGICAL_H = canvas.height / ZOOM;
    const assetBase = (canvas.dataset.assetBase || "/static/img/soc/pixel-office").replace(/\/$/, "");

    const ui = {
        shell: document.getElementById("soc-room-shell"),
        start: document.getElementById("soc-start"),
        pause: document.getElementById("soc-pause"),
        reset: document.getElementById("soc-reset"),
        fullscreen: document.getElementById("soc-fullscreen"),
        scenario: document.getElementById("soc-scenario"),
        statusBadge: document.getElementById("soc-status-badge"),
        statusLabel: document.getElementById("soc-status-label"),
        monitorStage: document.getElementById("soc-monitor-stage"),
        monitorCase: document.getElementById("soc-monitor-case"),
        activity: document.getElementById("soc-activity"),
        eventLog: document.getElementById("soc-event-log"),
        stageTrack: document.getElementById("soc-stage-track"),
        caseId: document.getElementById("soc-case-id"),
        caseIoc: document.getElementById("soc-case-ioc"),
    };

    // Scenario data — single source of truth, shared with soc_operations_advanced.js
    const SCENARIOS = {
        malicious: {
            id: "malicious",
            ioc: "44.238.29.244",
            caseId: "CASE-1024",
            verdict: "MALICIOUS",
            severity: "HIGH",
            score: 87,
            glitch: true,
        },
        suspicious: {
            id: "suspicious",
            ioc: "secure-update-login.net",
            caseId: "CASE-1042",
            verdict: "SUSPICIOUS",
            severity: "MEDIUM",
            score: 54,
            glitch: false,
        },
        clean: {
            id: "clean",
            ioc: "8.8.8.8",
            caseId: "CASE-1031",
            verdict: "CLEAN",
            severity: "LOW",
            score: 6,
            glitch: false,
        },
    };

    function getActiveScenario() {
        const key = ui.scenario?.value;
        return SCENARIOS[key] || SCENARIOS.malicious;
    }

    // Exposed for soc_operations_advanced.js
    window.SOC_SCENARIOS = SCENARIOS;
    window.SOC_GET_ACTIVE_SCENARIO = getActiveScenario;

    function buildStages(scenario) {
        return [
            { id: "idle", label: "Idle", duration: Infinity, activity: "Waiting for demo", monitor: "AWAITING IOC", event: "SOC room ready" },
            { id: "queued", label: "Queued", duration: 2.8, activity: `Dispatching IOC ${scenario.ioc} to SOC analysts`, monitor: "IOC QUEUED", event: "analysis.queued" },
            { id: "enrichment", label: "Enrich", duration: 4.4, activity: "Querying threat-intelligence sources", monitor: "ENRICHMENT", event: "enrichment.started" },
            { id: "correlation", label: "Correlate", duration: 4.2, activity: `Correlating IOC with ${brand} evidence`, monitor: "CORRELATING", event: "correlation.started" },
            { id: "scoring", label: "Score", duration: 3.8, activity: "Calculating risk score", monitor: `RISK SCORE: ${scenario.score}`, event: "scoring.started" },
            { id: "classification", label: "Classify", duration: 4.0, activity: `Verdict reached — ${scenario.verdict} (${scenario.severity})`, monitor: scenario.verdict, event: "threat.detected" },
            { id: "reporting", label: "Report", duration: 4.2, activity: "Generating Threat Intelligence Report", monitor: "BUILDING REPORT", event: "report.generated" },
            { id: "completed", label: "Complete", duration: Infinity, activity: "Analysis complete — report is ready", monitor: "ANALYSIS COMPLETE", event: "analysis.completed" },
        ];
    }

    let STAGES = buildStages(getActiveScenario());

    const FURNITURE_PATHS = {
        BIN: "furniture/BIN/BIN.png",
        BOOKSHELF: "furniture/BOOKSHELF/BOOKSHELF.png",
        CACTUS: "furniture/CACTUS/CACTUS.png",
        CLOCK: "furniture/CLOCK/CLOCK.png",
        COFFEE: "furniture/COFFEE/COFFEE.png",
        COFFEE_TABLE: "furniture/COFFEE_TABLE/COFFEE_TABLE.png",
        CUSHIONED_BENCH: "furniture/CUSHIONED_BENCH/CUSHIONED_BENCH.png",
        DESK_FRONT: "furniture/DESK/DESK_FRONT.png",
        DOUBLE_BOOKSHELF: "furniture/DOUBLE_BOOKSHELF/DOUBLE_BOOKSHELF.png",
        HANGING_PLANT: "furniture/HANGING_PLANT/HANGING_PLANT.png",
        LARGE_PAINTING: "furniture/LARGE_PAINTING/LARGE_PAINTING.png",
        LARGE_PLANT: "furniture/LARGE_PLANT/LARGE_PLANT.png",
        PC_FRONT_OFF: "furniture/PC/PC_FRONT_OFF.png",
        PC_FRONT_ON_1: "furniture/PC/PC_FRONT_ON_1.png",
        PC_FRONT_ON_2: "furniture/PC/PC_FRONT_ON_2.png",
        PC_FRONT_ON_3: "furniture/PC/PC_FRONT_ON_3.png",
        PC_SIDE: "furniture/PC/PC_SIDE.png",
        PLANT: "furniture/PLANT/PLANT.png",
        PLANT_2: "furniture/PLANT_2/PLANT_2.png",
        POT: "furniture/POT/POT.png",
        SMALL_PAINTING: "furniture/SMALL_PAINTING/SMALL_PAINTING.png",
        SMALL_PAINTING_2: "furniture/SMALL_PAINTING_2/SMALL_PAINTING_2.png",
        SMALL_TABLE_FRONT: "furniture/SMALL_TABLE/SMALL_TABLE_FRONT.png",
        SOFA_BACK: "furniture/SOFA/SOFA_BACK.png",
        SOFA_FRONT: "furniture/SOFA/SOFA_FRONT.png",
        SOFA_SIDE: "furniture/SOFA/SOFA_SIDE.png",
        TABLE_FRONT: "furniture/TABLE_FRONT/TABLE_FRONT.png",
        WHITEBOARD: "furniture/WHITEBOARD/WHITEBOARD.png",
        WOODEN_CHAIR_SIDE: "furniture/WOODEN_CHAIR/WOODEN_CHAIR_SIDE.png",
    };

    const images = new Map();
    const runtime = {
        layout: null,
        ready: false,
        running: false,
        paused: false,
        stageIndex: 0,
        stageElapsed: 0,
        clock: 0,
        lastFrame: performance.now(),
        eventStages: new Set(),
        particles: [],
        scenario: getActiveScenario(),
    };

    const agents = [
        createAgent(0, "NOVA", 0, 13, 8),
        createAgent(1, "BYTE", 1, 21, 12),
        createAgent(2, "ECHO", 2, 17, 6),
        createAgent(3, "LINK", 3, 10, 10),
    ];

    function createAgent(id, name, palette, col, row) {
        return {
            id,
            name,
            palette,
            x: col * TILE + TILE / 2,
            y: row * TILE + TILE / 2,
            route: [],
            direction: "down",
            mode: "idle",
            afterMove: "idle",
            frameTimer: 0,
            frame: 1,
            bubble: null,
        };
    }

    function loadImage(key, src) {
        return new Promise((resolve) => {
            const img = new Image();
            img.onload = () => {
                images.set(key, img);
                resolve(img);
            };
            img.onerror = () => resolve(null);
            img.src = src;
        });
    }

    async function loadAssets() {
        const tasks = [];
        for (let i = 0; i < 9; i += 1) {
            tasks.push(loadImage(`floor_${i}`, `${assetBase}/floors/floor_${i}.png`));
        }
        for (let i = 0; i < agents.length; i += 1) {
            tasks.push(loadImage(`char_${i}`, `${assetBase}/characters/char_${i}.png`));
        }
        for (const [type, path] of Object.entries(FURNITURE_PATHS)) {
            tasks.push(loadImage(type, `${assetBase}/${path}`));
        }
        if (canvas.dataset.serverRackSrc) {
            tasks.push(loadImage("SOCPOW_SERVER_RACK", canvas.dataset.serverRackSrc));
        }

        const layoutPromise = fetch(`${assetBase}/default-layout.json`, { cache: "no-store" })
            .then((response) => {
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return response.json();
            })
            .catch(() => createFallbackLayout());

        const [layout] = await Promise.all([layoutPromise, Promise.all(tasks)]);
        runtime.layout = layout;
        runtime.ready = true;
        renderFrame();
    }

    function createFallbackLayout() {
        const cols = 26;
        const rows = 16;
        const tiles = new Array(cols * rows).fill(1);
        for (let row = 0; row < rows; row += 1) {
            for (let col = 0; col < cols; col += 1) {
                if (row === 0 || row === rows - 1 || col === 0 || col === cols - 1) {
                    tiles[row * cols + col] = 0;
                } else if (col >= 14 && row < 8) {
                    tiles[row * cols + col] = 7;
                } else if (col >= 14 && row >= 8) {
                    tiles[row * cols + col] = 9;
                }
            }
        }
        return { cols, rows, tiles, furniture: [] };
    }

    function tilePoint(col, row) {
        return { x: col * TILE + TILE / 2, y: row * TILE + TILE / 2 };
    }

    function setRoute(agent, points, afterMove = "idle") {
        agent.route = points.map(([col, row]) => tilePoint(col, row));
        agent.afterMove = afterMove;
        if (agent.route.length) agent.mode = "walk";
    }

    const WANDER_POINTS = [[13, 6], [10, 4], [6, 4], [3, 2], [18, 12], [15, 12], [14, 8], [14, 4], [8, 4]];

    function wanderAgent(agent, dt) {
        if (agent.route.length) return;
        const next = WANDER_POINTS[Math.floor(Math.random() * WANDER_POINTS.length)];
        setRoute(agent, [next], "idle");
    }

    function applyScenarioToCaseCard(scenario) {
        if (ui.caseId) ui.caseId.textContent = scenario.caseId;
        if (ui.caseIoc) ui.caseIoc.textContent = `IOC: ${scenario.ioc}`;
    }

    function enterStage(index) {
        runtime.stageIndex = index;
        runtime.stageElapsed = 0;
        const stage = STAGES[index];
        const scenario = runtime.scenario;

        agents.forEach((agent) => {
            agent.bubble = null;
            agent.route = [];
        });

        switch (stage.id) {
            case "idle":
                resetAgent(agents[0], 6, 8, "idle", "down");
                resetAgent(agents[1], 21, 12, "idle", "down");
                break;
            case "queued":
                agents[0].bubble = "!";
                agents[1].bubble = "!";
                setRoute(agents[0], [[13, 6], [13, 4], [10, 4], [6, 4], [3, 2]], "type");
                setRoute(agents[1], [[18, 12], [15, 12], [14, 8], [14, 4], [10, 4], [8, 4]], "type");
                break;
            case "enrichment":
                setAt(agents[0], 3, 2, "type", "up");
                setAt(agents[1], 8, 4, "read", "up");
                agents[1].bubble = "…";
                break;
            case "correlation":
                setRoute(agents[0], [[6, 4], [10, 4], [12, 5], [12, 7]], "read");
                setAt(agents[1], 8, 4, "type", "up");
                break;
            case "scoring":
                setRoute(agents[0], [[12, 5], [10, 4], [6, 4], [3, 2]], "type");
                setRoute(agents[1], [[10, 4], [12, 4], [14, 4], [17, 4]], "read");
                break;
            case "classification":
                setAt(agents[0], 3, 2, "read", "up");
                setAt(agents[1], 17, 4, "read", "right");
                agents[0].bubble = scenario.glitch ? "!" : "✓";
                agents[1].bubble = scenario.glitch ? "!" : "✓";
                break;
            case "reporting":
                setAt(agents[0], 3, 2, "type", "up");
                setRoute(agents[1], [[17, 6], [17, 8], [19, 8], [23, 10]], "type");
                break;
            case "completed":
                setRoute(agents[0], [[6, 4], [10, 4], [13, 4], [15, 8], [18, 9]], "idle");
                setAt(agents[1], 23, 10, "idle", "down");
                agents[0].bubble = "✓";
                agents[1].bubble = "✓";
                runtime.running = false;
                runtime.paused = false;
                if (ui.scenario) ui.scenario.disabled = false;
                break;
        }

        if (!runtime.eventStages.has(stage.id)) {
            runtime.eventStages.add(stage.id);
            appendEvent(stage);
        }
        updateUI();
    }

    function resetAgent(agent, col, row, mode, direction) {
        const point = tilePoint(col, row);
        agent.x = point.x;
        agent.y = point.y;
        agent.route = [];
        agent.mode = mode;
        agent.afterMove = mode;
        agent.direction = direction;
        agent.frame = 1;
        agent.frameTimer = 0;
        agent.bubble = null;
    }

    function setAt(agent, col, row, mode, direction) {
        resetAgent(agent, col, row, mode, direction);
    }

    function updateAgent(agent, dt) {
        agent.frameTimer += dt;
        const frameDuration = agent.mode === "walk" ? 0.15 : 0.3;
        if (agent.frameTimer >= frameDuration) {
            agent.frameTimer -= frameDuration;
            agent.frame = (agent.frame + 1) % (agent.mode === "walk" ? 4 : 2);
        }

        if (!agent.route.length) return;

        const target = agent.route[0];
        const dx = target.x - agent.x;
        const dy = target.y - agent.y;
        const distance = Math.hypot(dx, dy);
        if (Math.abs(dx) > Math.abs(dy)) agent.direction = dx > 0 ? "right" : "left";
        else if (Math.abs(dy) > 0.01) agent.direction = dy > 0 ? "down" : "up";

        const step = 48 * dt;
        if (distance <= step || distance < 0.01) {
            agent.x = target.x;
            agent.y = target.y;
            agent.route.shift();
            if (!agent.route.length) {
                agent.mode = agent.afterMove;
                agent.frame = 0;
                agent.frameTimer = 0;
            }
        } else {
            agent.x += (dx / distance) * step;
            agent.y += (dy / distance) * step;
        }
    }

    function appendEvent(stage) {
        if (!ui.eventLog) return;
        const item = document.createElement("li");
        item.dataset.stage = stage.id;
        item.className = "is-active";
        const eventName = document.createElement("span");
        eventName.textContent = stage.event;
        const time = document.createElement("time");
        time.textContent = demoTimestamp(runtime.eventStages.size - 1);
        item.append(eventName, time);
        ui.eventLog.querySelectorAll("li").forEach((row) => row.classList.remove("is-active"));
        item.classList.add("is-active");
        ui.eventLog.appendChild(item);
        ui.eventLog.scrollTop = ui.eventLog.scrollHeight;
    }

    function demoTimestamp(offset) {
        const seconds = 30 + offset * 4;
        return `20:30:${String(seconds).padStart(2, "0")}Z`;
    }

    function buildStageTrack() {
        if (!ui.stageTrack) return;
        ui.stageTrack.replaceChildren();
        STAGES.forEach((stage) => {
            const item = document.createElement("div");
            item.className = "soc-stage-step";
            item.dataset.stage = stage.id;
            const bar = document.createElement("span");
            bar.className = "soc-stage-bar";
            const label = document.createElement("small");
            label.textContent = stage.label;
            item.append(bar, label);
            ui.stageTrack.appendChild(item);
        });
    }

    function updateUI() {
        const stage = STAGES[runtime.stageIndex];
        if (ui.statusBadge) ui.statusBadge.dataset.state = stage.id;
        if (ui.statusLabel) ui.statusLabel.textContent = `STATUS: ${stage.id.toUpperCase()}`;
        if (ui.monitorStage) ui.monitorStage.textContent = stage.monitor;
        if (ui.monitorCase) ui.monitorCase.textContent = runtime.stageIndex === 0 ? "CASE: DEMO-0001" : `CASE: ${runtime.scenario.caseId} · IOC ${runtime.scenario.ioc}`;
        if (ui.activity) ui.activity.textContent = stage.activity;
        if (ui.pause) {
            ui.pause.disabled = !runtime.running && !runtime.paused;
            ui.pause.textContent = runtime.paused ? "Resume" : "Pause";
        }
        if (ui.start) ui.start.disabled = runtime.running || runtime.paused;

        if (ui.stageTrack) {
            ui.stageTrack.querySelectorAll(".soc-stage-step").forEach((item, index) => {
                item.classList.toggle("is-complete", index < runtime.stageIndex);
                item.classList.toggle("is-active", index === runtime.stageIndex);
            });
        }
    }

    function resetDemo() {
        runtime.running = false;
        runtime.paused = false;
        runtime.clock = 0;
        runtime.eventStages.clear();
        runtime.particles = [];
        runtime.scenario = getActiveScenario();
        STAGES = buildStages(runtime.scenario);
        applyScenarioToCaseCard(runtime.scenario);
        if (ui.scenario) ui.scenario.disabled = false;
        if (ui.eventLog) ui.eventLog.replaceChildren();
        enterStage(0);
    }

    function startDemo() {
        runtime.scenario = getActiveScenario();
        STAGES = buildStages(runtime.scenario);
        applyScenarioToCaseCard(runtime.scenario);
        runtime.running = true;
        runtime.paused = false;
        runtime.eventStages.clear();
        runtime.particles = [];
        if (ui.scenario) ui.scenario.disabled = true;
        if (ui.eventLog) ui.eventLog.replaceChildren();
        enterStage(1);
    }

    function togglePause() {
        if (!runtime.running && !runtime.paused) return;
        runtime.paused = !runtime.paused;
        runtime.running = !runtime.paused;
        updateUI();
    }

    function toggleFullscreen() {
        if (!ui.shell) return;
        if (document.fullscreenElement) document.exitFullscreen();
        else ui.shell.requestFullscreen?.();
    }

    function update(dt) {
        runtime.clock += dt;
        agents.forEach((agent) => updateAgent(agent, dt));
        [agents[2], agents[3]].forEach((agent) => wanderAgent(agent, dt));

        if (runtime.running) {
            runtime.stageElapsed += dt;
            const stage = STAGES[runtime.stageIndex];
            if (runtime.stageElapsed >= stage.duration && runtime.stageIndex < STAGES.length - 1) {
                enterStage(runtime.stageIndex + 1);
            }
        }

        if (STAGES[runtime.stageIndex].id === "correlation") updateParticles(dt);
        else runtime.particles = [];
    }

    function updateParticles(dt) {
        if (Math.random() < dt * 9) {
            runtime.particles.push({ progress: 0, speed: 0.55 + Math.random() * 0.35, lane: Math.random() });
        }
        runtime.particles.forEach((particle) => { particle.progress += dt * particle.speed; });
        runtime.particles = runtime.particles.filter((particle) => particle.progress < 1);
    }

    function renderFrame() {
        ctx.save();
        ctx.setTransform(ZOOM, 0, 0, ZOOM, 0, 0);
        ctx.imageSmoothingEnabled = false;
        ctx.clearRect(0, 0, LOGICAL_W, LOGICAL_H);
        ctx.fillStyle = "#070a10";
        ctx.fillRect(0, 0, LOGICAL_W, LOGICAL_H);

        if (!runtime.ready || !runtime.layout) {
            drawLoading();
            ctx.restore();
            return;
        }

        drawTiles(runtime.layout);
        drawScene(runtime.layout);
        drawSocpowRack();
        drawCorrelationFlow();
        drawThreatAlert();
        drawVignette();
        ctx.restore();
    }

    function drawLoading() {
        ctx.fillStyle = "#22d3ee";
        ctx.font = "8px monospace";
        ctx.textAlign = "center";
        ctx.fillText("LOADING PIXEL OFFICE ASSETS...", LOGICAL_W / 2, LOGICAL_H / 2);
    }

    function drawTiles(layout) {
        const { cols, rows, tiles } = layout;
        for (let row = 0; row < rows; row += 1) {
            for (let col = 0; col < cols; col += 1) {
                const type = tiles[row * cols + col];
                const x = col * TILE;
                const y = row * TILE;
                drawTile(type, col, row, x, y);
            }
        }
    }

    function drawTile(type, col, row, x, y) {
        if (type === 0) {
            ctx.fillStyle = row === 0 ? "#111a2a" : "#172236";
            ctx.fillRect(x, y, TILE, TILE);
            ctx.fillStyle = "rgba(255,255,255,.025)";
            ctx.fillRect(x, y + TILE - 2, TILE, 2);
            return;
        }

        if (type === 9) {
            const dark = (col + row) % 2 === 0;
            ctx.fillStyle = dark ? "#303745" : "#c8ced6";
            ctx.fillRect(x, y, TILE, TILE);
            ctx.fillStyle = "rgba(0,0,0,.09)";
            ctx.fillRect(x, y + TILE - 1, TILE, 1);
            return;
        }

        const colors = {
            1: "#694328",
            2: "#3a4a5f",
            3: "#4b3847",
            4: "#315547",
            5: "#49483b",
            6: "#3b4458",
            7: "#345b7d",
            8: "#5a3f5f",
        };
        ctx.fillStyle = colors[type] || "#414b59";
        ctx.fillRect(x, y, TILE, TILE);
        const floorImage = images.get(`floor_${Math.max(0, Math.min(8, type - 1))}`);
        if (floorImage) {
            ctx.save();
            ctx.globalAlpha = type === 1 ? 0.48 : 0.24;
            ctx.globalCompositeOperation = "screen";
            ctx.drawImage(floorImage, x, y, TILE, TILE);
            ctx.restore();
        }
        ctx.fillStyle = "rgba(0,0,0,.09)";
        ctx.fillRect(x, y + TILE - 1, TILE, 1);
    }

    function drawScene(layout) {
        const items = [];
        const pcFrame = 1 + (Math.floor(runtime.clock / 0.2) % 3);
        const pcActive = runtime.stageIndex >= 2 && runtime.stageIndex <= 6;

        for (const furniture of layout.furniture || []) {
            let type = furniture.type;
            const mirrored = type.endsWith(":left");
            if (mirrored) type = type.replace(":left", "");
            if (type === "PC_FRONT_OFF" && pcActive) type = `PC_FRONT_ON_${pcFrame}`;
            const image = images.get(type);
            if (!image) continue;
            items.push({
                kind: "furniture",
                image,
                mirrored,
                x: furniture.col * TILE,
                y: furniture.row * TILE,
                z: furniture.row * TILE + image.height,
            });
        }

        for (const agent of agents) {
            items.push({ kind: "agent", agent, z: agent.y + 4 });
        }

        items.sort((a, b) => a.z - b.z);
        items.forEach((item) => {
            if (item.kind === "furniture") drawFurniture(item);
            else drawAgent(item.agent);
        });
    }

    function drawFurniture(item) {
        if (!item.mirrored) {
            ctx.drawImage(item.image, item.x, item.y);
            return;
        }
        ctx.save();
        ctx.translate(item.x + item.image.width, item.y);
        ctx.scale(-1, 1);
        ctx.drawImage(item.image, 0, 0);
        ctx.restore();
    }

    function drawAgent(agent) {
        const image = images.get(`char_${agent.palette}`);
        if (!image) return;

        let row = 0;
        let mirror = false;
        if (agent.direction === "up") row = 1;
        if (agent.direction === "right" || agent.direction === "left") row = 2;
        if (agent.direction === "left") mirror = true;

        let frame = 1;
        if (agent.mode === "walk") frame = [0, 1, 2, 1][agent.frame % 4];
        if (agent.mode === "type") frame = 3 + (agent.frame % 2);
        if (agent.mode === "read") frame = 5 + (agent.frame % 2);

        const dx = Math.round(agent.x - 8);
        const sittingOffset = agent.mode === "type" || agent.mode === "read" ? 6 : 0;
        const dy = Math.round(agent.y - 28 + sittingOffset);

        ctx.save();
        if (mirror) {
            ctx.translate(dx + 16, dy);
            ctx.scale(-1, 1);
            ctx.drawImage(image, frame * 16, row * 32, 16, 32, 0, 0, 16, 32);
        } else {
            ctx.drawImage(image, frame * 16, row * 32, 16, 32, dx, dy, 16, 32);
        }
        ctx.restore();

        drawAgentLabel(agent, dx + 8, dy - 2);
        if (agent.bubble) drawBubble(agent.bubble, dx + 12, dy - 13);
    }

    function drawAgentLabel(agent, x, y) {
        const text = agent.name;
        ctx.font = "bold 5px monospace";
        const width = Math.ceil(ctx.measureText(text).width) + 5;
        ctx.fillStyle = "rgba(3,8,15,.82)";
        ctx.fillRect(Math.round(x - width / 2), Math.round(y - 6), width, 8);
        ctx.strokeStyle = "rgba(34,211,238,.45)";
        ctx.lineWidth = 0.5;
        ctx.strokeRect(Math.round(x - width / 2) + 0.25, Math.round(y - 6) + 0.25, width - 0.5, 7.5);
        ctx.fillStyle = "#dff8ff";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(text, Math.round(x), Math.round(y - 2));
    }

    function drawBubble(symbol, x, y) {
        ctx.fillStyle = "#f7fbff";
        ctx.fillRect(Math.round(x - 6), Math.round(y - 8), 12, 10);
        ctx.fillStyle = "#f7fbff";
        ctx.fillRect(Math.round(x - 1), Math.round(y + 2), 3, 3);
        ctx.fillStyle = symbol === "!" ? "#ef4444" : symbol === "✓" ? "#16a34a" : "#334155";
        ctx.font = "bold 7px monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(symbol, Math.round(x), Math.round(y - 3));
    }

    function drawSocpowRack() {
        const x = 12 * TILE;
        const y = 6 * TILE;
        const rack = images.get("SOCPOW_SERVER_RACK");
        if (rack) {
            ctx.drawImage(rack, x, y, 32, 64);
            return;
        }

        ctx.fillStyle = "#111827";
        ctx.fillRect(x + 3, y, 26, 62);
        ctx.strokeStyle = "#53627a";
        ctx.lineWidth = 1;
        ctx.strokeRect(x + 3.5, y + 0.5, 25, 61);
        for (let i = 0; i < 6; i += 1) {
            ctx.fillStyle = "#202b3d";
            ctx.fillRect(x + 6, y + 5 + i * 9, 20, 6);
            ctx.fillStyle = (i + Math.floor(runtime.clock * 3)) % 3 === 0 ? "#22d3ee" : "#4ade80";
            ctx.fillRect(x + 8, y + 7 + i * 9, 2, 2);
        }
    }

    function drawCorrelationFlow() {
        if (STAGES[runtime.stageIndex].id !== "correlation") return;
        const from = tilePoint(8, 4);
        const to = tilePoint(13, 7);
        ctx.save();
        ctx.strokeStyle = "rgba(34,211,238,.28)";
        ctx.setLineDash([2, 2]);
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.stroke();
        ctx.setLineDash([]);
        runtime.particles.forEach((particle) => {
            const p = particle.progress;
            const x = from.x + (to.x - from.x) * p;
            const y = from.y + (to.y - from.y) * p + (particle.lane - 0.5) * 5;
            ctx.fillStyle = particle.lane > 0.5 ? "#22d3ee" : "#4ade80";
            ctx.fillRect(Math.round(x) - 1, Math.round(y) - 1, 3, 3);
        });
        ctx.restore();
    }

    function drawThreatAlert() {
        if (STAGES[runtime.stageIndex].id !== "classification") return;
        if (!runtime.scenario.glitch) return;
        const alpha = 0.05 + (Math.sin(runtime.clock * 7) + 1) * 0.035;
        ctx.fillStyle = `rgba(239,68,68,${alpha})`;
        ctx.fillRect(0, 0, LOGICAL_W, LOGICAL_H);
        ctx.strokeStyle = "rgba(251,93,103,.85)";
        ctx.lineWidth = 2;
        ctx.strokeRect(2, 2, LOGICAL_W - 4, LOGICAL_H - 4);
        ctx.fillStyle = "rgba(78,10,16,.88)";
        ctx.fillRect(LOGICAL_W / 2 - 42, 5, 84, 11);
        ctx.fillStyle = "#ff8b93";
        ctx.font = "bold 6px monospace";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText("HIGH THREAT DETECTED", LOGICAL_W / 2, 10.5);
    }

    function drawVignette() {
        const gradient = ctx.createRadialGradient(LOGICAL_W / 2, LOGICAL_H / 2, 70, LOGICAL_W / 2, LOGICAL_H / 2, 245);
        gradient.addColorStop(0, "rgba(0,0,0,0)");
        gradient.addColorStop(1, "rgba(0,0,0,.3)");
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 0, LOGICAL_W, LOGICAL_H);
    }

    function frame(now) {
        const dt = Math.min(0.1, Math.max(0, (now - runtime.lastFrame) / 1000));
        runtime.lastFrame = now;
        if (!runtime.paused) update(dt);
        renderFrame();
        requestAnimationFrame(frame);
    }

    buildStageTrack();
    resetDemo();
    loadAssets();

    ui.start?.addEventListener("click", startDemo);
    ui.pause?.addEventListener("click", togglePause);
    ui.reset?.addEventListener("click", resetDemo);
    ui.fullscreen?.addEventListener("click", toggleFullscreen);
    ui.scenario?.addEventListener("change", () => {
        if (runtime.running) return;
        resetDemo();
    });
    document.addEventListener("fullscreenchange", () => {
        if (ui.fullscreen) ui.fullscreen.textContent = document.fullscreenElement ? "Exit Fullscreen" : "Fullscreen";
    });

    requestAnimationFrame((now) => {
        runtime.lastFrame = now;
        requestAnimationFrame(frame);
    });
})();
