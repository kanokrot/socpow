(function () {
    'use strict';

    const byId = (id) => document.getElementById(id);
    const tree = byId('tr-tree');
    const search = byId('tr-search');
    const selected = new Set();
    const resultFilters = document.querySelectorAll('[data-result-filter]');
    let mapWidth = 1000;
    let mapHeight = 350;
    const selectedTopicIds = new Set();
    let files = [];
    let topics = {};
    let collectionActive = false;
    let runActive = false;
    let outputOffset = 0;
    let pollTimer = null;
    let activeFilter = 'all';
    let activeTopic = 'all';
    let results = [];
    let testInfo = {};
    let lastRun = null;
    let mapPoints = [];
    let mapPointByNode = new Map();
    let mapResults = new Map();
    let hoveredMapPoint = null;
    let focusedMapIndex = 0;
    let mapSignature = '';
    let mapSprites = null;
    let dotsRedrawPending = false;
    let mapResizeObserver = null;

    const lower = (value) => String(value || '').toLocaleLowerCase();
    const findFile = (nodeid) => nodeid.split('::', 1)[0];
    const infoFor = (nodeid) => testInfo[nodeid] || testInfo[nodeid.split('[', 1)[0]] || null;
    const topicData = (id) => topics[id] || { name: id.replaceAll('_', ' '), description: 'Collected system tests.' };

    function humanizedFallback(nodeid) {
        const name = nodeid.split('::').pop().split('[')[0].replace(/^test_/, '').replaceAll('_', ' ').trim();
        return name ? name[0].toLocaleUpperCase() + name.slice(1) : 'Unnamed test';
    }

    function testTitle(nodeid) {
        const details = infoFor(nodeid) || {};
        const title = details.title || humanizedFallback(nodeid);
        const readable = title ? title[0].toLocaleUpperCase() + title.slice(1) : 'Unnamed test';
        return details.group ? `${details.group}: ${readable}` : readable;
    }

    function mergeInfo(info) {
        if (info && typeof info === 'object') testInfo = { ...testInfo, ...info };
    }

    function mergeTopics(value) {
        if (value && typeof value === 'object') topics = { ...topics, ...value };
    }

    async function api(url, options) {
        const response = await window.fetch(url, options || {});
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
        return data;
    }

    function selectedTestCount() {
        return files.reduce((count, file) => {
            if (!file.selectable) return count;
            if (selected.has(file.path)) return count + Number(file.count || 0);
            return count + file.nodeids.filter((nodeid) => selected.has(nodeid)).length;
        }, 0);
    }

    function setFileSelection(file, checked) {
        if (!file || !file.selectable) return;
        if (checked) {
            selected.add(file.path);
            file.nodeids.forEach((nodeid) => selected.delete(nodeid));
        } else selected.delete(file.path);
    }

    function setTopicSelection(topic, checked) {
        files.filter((file) => file.topic === topic && file.selectable).forEach((file) => setFileSelection(file, checked));
    }

    function updateButtons() {
        const busy = collectionActive || runActive;
        const selectedCount = selectedTestCount();
        byId('tr-refresh').disabled = busy;
        byId('tr-run-all').disabled = busy || !files.some((file) => file.selectable && file.count > 0);
        byId('tr-run-selected').disabled = busy || selectedCount === 0;
        byId('tr-selected-count').textContent = String(selectedCount);
        byId('tr-selection-summary').textContent = `${selectedCount} ${selectedCount === 1 ? 'test' : 'tests'} selected`;
        byId('tr-run-failed').disabled = busy || !(lastRun && lastRun.results && lastRun.results.some((item) => item.outcome === 'failed'));
        byId('tr-failed-action-count').textContent = String(lastRun && lastRun.results ? lastRun.results.filter((item) => item.outcome === 'failed').length : 0);
        byId('tr-cancel').disabled = !runActive;
        byId('tr-select-matching').disabled = busy || !files.length;
        byId('tr-clear').disabled = busy || selected.size === 0;
        tree.querySelectorAll('.tr-topic-check').forEach((checkbox) => {
            const topic = checkbox.dataset.topic;
            const matching = files.filter((file) => file.topic === topic && file.selectable);
            const allSelected = matching.length > 0 && matching.every((file) => selected.has(file.path) || file.nodeids.every((nodeid) => selected.has(nodeid)));
            const someSelected = matching.some((file) => selected.has(file.path) || file.nodeids.some((nodeid) => selected.has(nodeid)));
            checkbox.checked = allSelected;
            checkbox.indeterminate = someSelected && !allSelected;
            checkbox.disabled = busy || matching.length === 0;
        });
        tree.querySelectorAll('.tr-file-check').forEach((checkbox) => {
            const file = files.find((item) => item.path === checkbox.value);
            if (!file) return;
            const allNodes = file.nodeids.length > 0 && file.nodeids.every((nodeid) => selected.has(nodeid));
            checkbox.checked = selected.has(file.path);
            checkbox.indeterminate = !checkbox.checked && allNodes;
            checkbox.disabled = busy || !file.selectable;
        });
        tree.querySelectorAll('.tr-test-check').forEach((checkbox) => {
            const file = files.find((item) => item.path === checkbox.dataset.file);
            checkbox.checked = !!file && (selected.has(file.path) || selected.has(checkbox.value));
            checkbox.disabled = busy || !file || !file.selectable;
        });
    }

    function resultMap() { return new Map(results.map((item) => [item.nodeid, item])); }

    function renderTopicFilters() {
        const container = byId('tr-topic-filters');
        container.replaceChildren();
        const ids = ['all', ...new Set(files.map((file) => file.topic || 'other'))];
        ids.forEach((id) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'tr-topic-chip';
            button.dataset.topic = id;
            button.setAttribute('aria-pressed', String(activeTopic === id));
            button.textContent = id === 'all' ? 'All topics' : topicData(id).name;
            button.addEventListener('click', () => {
                activeTopic = id;
                renderTopicFilters();
                applyTreeFilter();
            });
            container.append(button);
        });
    }

    function makeErrorRow(file) {
        const error = document.createElement('div');
        error.className = 'tr-error-file';
        const name = document.createElement('strong');
        name.textContent = file.path;
        const message = document.createElement('p');
        const rawError = String(file.error || 'Collection failed');
        message.textContent = `Can't run: ${rawError.split(/\r?\n/).find((line) => line.trim()) || 'collection failed'}`;
        error.append(name, message);
        return error;
    }

    function makeTestRow(file, nodeid, result) {
        const row = document.createElement('label');
        row.className = 'tr-test-row';
        row.dataset.nodeid = nodeid;
        const details = infoFor(nodeid) || {};
        row.dataset.search = lower(`${file.path} ${testTitle(nodeid)} ${details.doc || ''} ${(details.checks || []).join(' ')} ${file.topic || ''}`);
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'tr-check tr-test-check';
        checkbox.value = nodeid;
        checkbox.dataset.file = file.path;
        checkbox.addEventListener('change', () => {
            if (checkbox.checked) {
                selected.delete(file.path);
                selected.add(nodeid);
            } else selected.delete(nodeid);
            updateButtons();
        });
        const open = document.createElement('button');
        open.type = 'button';
        open.className = 'tr-test-open';
        open.textContent = testTitle(nodeid);
        open.addEventListener('click', (event) => {
            event.preventDefault();
            openTestInfo(nodeid, result && result.outcome, result && result.message);
        });
        const name = document.createElement('span');
        name.className = 'tr-test-name';
        name.append(open);
        row.append(checkbox, name);
        if (result) {
            const status = document.createElement('span');
            status.className = `tr-test-status ${result.outcome || ''}`;
            status.textContent = result.outcome === 'passed' ? '✓' : result.outcome === 'failed' ? '!' : result.outcome === 'skipped' ? '–' : '';
            row.append(status);
        }
        return row;
    }

    function renderTree() {
        tree.replaceChildren();
        const knownResults = resultMap();
        const byTopic = new Map();
        files.forEach((file) => {
            const topic = file.topic || 'other';
            if (!byTopic.has(topic)) byTopic.set(topic, []);
            byTopic.get(topic).push(file);
        });
        if (!byTopic.size) {
            const empty = document.createElement('p');
            empty.className = 'tr-empty-inline';
            empty.textContent = 'No tests are available in the collected list.';
            tree.append(empty);
        }
        [...byTopic.entries()].sort((a, b) => topicData(a[0]).name.localeCompare(topicData(b[0]).name)).forEach(([topic, topicFiles]) => {
            const meta = topicData(topic);
            const allNodeids = topicFiles.flatMap((file) => file.nodeids);
            const failedFiles = topicFiles.filter((file) => file.error);
            const card = document.createElement('article');
            card.className = 'tr-topic-card';
            card.dataset.topic = topic;
            card.dataset.search = lower(`${meta.name} ${meta.description} ${topicFiles.map((file) => file.path).join(' ')}`);
            const head = document.createElement('div');
            head.className = 'tr-topic-head';
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'tr-check tr-topic-check';
            checkbox.dataset.topic = topic;
            checkbox.setAttribute('aria-label', `Select all ${allNodeids.length} tests in ${meta.name}`);
            checkbox.addEventListener('change', () => {
                setTopicSelection(topic, checkbox.checked);
                updateButtons();
            });
            const expander = document.createElement('button');
            expander.type = 'button';
            expander.className = 'tr-topic-expander';
            const name = document.createElement('strong');
            name.textContent = meta.name;
            const description = document.createElement('small');
            description.textContent = meta.description;
            expander.append(name, description);
            const count = document.createElement('span');
            count.className = 'tr-topic-count';
            count.textContent = `${allNodeids.length} ${allNodeids.length === 1 ? 'test' : 'tests'}`;
            const arrow = document.createElement('button');
            arrow.type = 'button';
            arrow.className = 'tr-topic-arrow';
            arrow.textContent = '⌄';
            arrow.setAttribute('aria-label', `Expand ${meta.name}`);
            arrow.setAttribute('aria-expanded', 'false');
            const list = document.createElement('div');
            list.className = 'tr-topic-tests';
            list.hidden = true;
            const fileGroups = document.createElement('div');
            const fileOrder = [...topicFiles].sort((a, b) => a.path.localeCompare(b.path));
            const visibleNodeids = allNodeids;
            const collapsedLimit = 48;
            let expandedAll = false;
            const testElements = [];
            fileOrder.forEach((file) => {
                const group = document.createElement('div');
                group.className = 'tr-file-group';
                group.dataset.file = file.path;
                if (file.error) {
                    group.append(makeErrorRow(file));
                    return;
                }
                const fileTitle = document.createElement('p');
                fileTitle.className = 'tr-file-title';
                fileTitle.textContent = file.path;
                group.append(fileTitle);
                file.nodeids.forEach((nodeid) => {
                    const row = makeTestRow(file, nodeid, knownResults.get(nodeid));
                    testElements.push(row);
                    group.append(row);
                });
                fileGroups.append(group);
            });
            list.append(fileGroups);
            const moreCount = Math.max(0, visibleNodeids.length - collapsedLimit);
            let moreButton = null;
            if (moreCount) {
                moreButton = document.createElement('button');
                moreButton.type = 'button';
                moreButton.className = 'tr-topic-more';
                moreButton.textContent = `+ ${moreCount} more tests`;
                moreButton.addEventListener('click', () => {
                    expandedAll = !expandedAll;
                    moreButton.textContent = expandedAll ? 'Show fewer tests' : `+ ${moreCount} more tests`;
                    testElements.forEach((row, index) => { if (index >= collapsedLimit) row.hidden = !expandedAll; });
                });
                list.append(moreButton);
            }
            testElements.forEach((row, index) => { if (index >= collapsedLimit) row.hidden = true; });
            const toggle = () => {
                list.hidden = !list.hidden;
                card.classList.toggle('is-open', !list.hidden);
                arrow.setAttribute('aria-expanded', String(!list.hidden));
                arrow.setAttribute('aria-label', `${list.hidden ? 'Expand' : 'Collapse'} ${meta.name}`);
            };
            expander.addEventListener('click', toggle);
            arrow.addEventListener('click', toggle);
            head.append(checkbox, expander, count, arrow);
            card.append(head, list);
            tree.append(card);
        });
        renderTopicFilters();
        applyTreeFilter();
        updateButtons();
    }

    function applyTreeFilter() {
        const query = lower(search.value.trim());
        tree.querySelectorAll('.tr-topic-card').forEach((card) => {
            const topicMatch = activeTopic === 'all' || card.dataset.topic === activeTopic;
            const cardMatch = !query || card.dataset.search.includes(query);
            const tests = [...card.querySelectorAll('.tr-test-row')];
            let visibleCount = 0;
            tests.forEach((row) => {
                const visible = !query || cardMatch || row.dataset.search.includes(query);
                row.hidden = !visible || (!query && tests.indexOf(row) >= 48 && !card.querySelector('.tr-topic-more')?.textContent.includes('fewer'));
                if (visible) visibleCount += 1;
            });
            card.hidden = !topicMatch || (!!query && !cardMatch && visibleCount === 0);
            if (query && !card.hidden) {
                const list = card.querySelector('.tr-topic-tests');
                list.hidden = false;
                card.classList.add('is-open');
                card.querySelector('.tr-topic-arrow').setAttribute('aria-expanded', 'true');
            }
        });
    }

    function updateTopicResults() {
        const container = byId('tr-topic-health');
        container.replaceChildren();
        const grouped = new Map();
        files.forEach((file) => {
            const topic = file.topic || 'other';
            if (!grouped.has(topic)) grouped.set(topic, []);
            if (file.selectable) grouped.get(topic).push(...file.nodeids);
        });
        const byNode = resultMap();
        [...grouped.entries()].sort((a, b) => topicData(a[0]).name.localeCompare(topicData(b[0]).name)).forEach(([topic, nodeids]) => {
            const counts = { passed: 0, failed: 0, skipped: 0 };
            nodeids.forEach((nodeid) => {
                const result = byNode.get(nodeid);
                if (result && counts[result.outcome] !== undefined) counts[result.outcome] += 1;
            });
            const done = counts.passed + counts.failed + counts.skipped;
            const row = document.createElement('div');
            row.className = 'tr-health-row';
            const head = document.createElement('div');
            head.className = 'tr-health-head';
            const name = document.createElement('span');
            name.textContent = topicData(topic).name;
            const state = document.createElement('small');
            state.textContent = done ? `${counts.passed} pass · ${counts.failed} fail` : 'Not run';
            head.append(name, state);
            const bar = document.createElement('div');
            bar.className = 'tr-health-bar';
            if (done) {
                ['passed', 'failed', 'skipped'].forEach((outcome) => {
                    const segment = document.createElement('i');
                    segment.className = outcome;
                    segment.style.width = `${counts[outcome] * 100 / Math.max(done, 1)}%`;
                    bar.append(segment);
                });
            }
            row.append(head, bar);
            container.append(row);
        });
        byId('tr-health-caption').textContent = results.length ? `${results.length} results reported` : 'No run yet';
    }

    function setRing(percent) {
        const circumference = 2 * Math.PI * 51;
        byId('tr-ring-progress').style.strokeDasharray = String(circumference);
        byId('tr-ring-progress').style.strokeDashoffset = String(circumference * (1 - percent / 100));
        byId('tr-pass-percent').textContent = percent === null ? '—' : `${percent}%`;
    }

    function updateHero(items) {
        const counts = { passed: 0, failed: 0, skipped: 0 };
        items.forEach((item) => { if (counts[item.outcome] !== undefined) counts[item.outcome] += 1; });
        const expected = lastRun ? Number(lastRun.expected_count || items.length) : files.reduce((sum, file) => sum + (file.selectable ? Number(file.count || 0) : 0), 0);
        const done = counts.passed + counts.failed + counts.skipped;
        const denominator = Math.max(expected, done, 1);
        const progress = Math.min(100, Math.round(done * 100 / denominator));
        const passPercent = done ? Math.round(counts.passed * 100 / done) : null;
        setRing(passPercent);
        byId('tr-passed').textContent = String(counts.passed);
        byId('tr-failed').textContent = String(counts.failed);
        byId('tr-skipped').textContent = String(counts.skipped);
        [['passed', counts.passed], ['failed', counts.failed], ['skipped', counts.skipped], ['pending', Math.max(0, expected - done)]].forEach(([key, count]) => {
            byId(`tr-progress-${key}`).style.width = `${Math.min(100, count * 100 / denominator)}%`;
        });
        byId('tr-progress-passed').parentElement.setAttribute('aria-valuenow', String(progress));
        byId('tr-total-caption').textContent = lastRun ? `${done} of ${expected} tests reported` : `${expected} collected tests`;
        if (!lastRun || lastRun.status === 'empty') {
            byId('tr-run-summary').textContent = 'No tests have run yet';
            byId('tr-run-caption').textContent = `${expected} collected tests are ready to run.`;
        } else if (runActive) {
            byId('tr-run-summary').textContent = `${counts.failed} tests failed so far`;
            byId('tr-run-caption').textContent = `Running ${lastRun.mode || 'selected'} tests · ${done} of ${expected} results reported.`;
        } else if (counts.failed) {
            byId('tr-run-summary').textContent = `${counts.failed} ${counts.failed === 1 ? 'test' : 'tests'} failed`;
            byId('tr-run-caption').textContent = `${counts.passed} passed and ${counts.skipped} skipped in this ${lastRun.mode || 'selected'} run.`;
        } else if (done) {
            byId('tr-run-summary').textContent = `All ${counts.passed} of ${expected} tests passed`;
            byId('tr-run-caption').textContent = `${counts.skipped} skipped · ${Math.max(0, expected - done)} not reported in this ${lastRun.mode || 'selected'} run.`;
        } else {
            byId('tr-run-summary').textContent = 'No test results were reported';
            byId('tr-run-caption').textContent = lastRun.error || 'The run did not produce a result report.';
        }
    }

    function renderBreakdownAndResults(items) {
        results = items || [];
        const counts = { passed: 0, failed: 0, skipped: 0 };
        results.forEach((item) => { if (counts[item.outcome] !== undefined) counts[item.outcome] += 1; });
        byId('tr-filter-all-count').textContent = String(results.length);
        byId('tr-filter-passed-count').textContent = String(counts.passed);
        byId('tr-filter-failed-count').textContent = String(counts.failed);
        byId('tr-filter-skipped-count').textContent = String(counts.skipped);
        const body = byId('tr-results');
        body.replaceChildren();
        if (!results.length) {
            const row = document.createElement('tr');
            row.className = 'tr-empty-row';
            const cell = document.createElement('td');
            cell.colSpan = 5;
            cell.textContent = runActive ? 'Waiting for test results…' : 'No test results yet.';
            row.append(cell);
            body.append(row);
        }
        results.forEach((result) => {
            const row = document.createElement('tr');
            row.dataset.outcome = result.outcome;
            row.dataset.search = lower(`${testTitle(result.nodeid)} ${result.nodeid}`);
            const test = document.createElement('td');
            test.textContent = testTitle(result.nodeid);
            if (result.message && ['failed', 'skipped'].includes(result.outcome)) {
                const why = document.createElement('div');
                why.className = 'tr-why';
                why.textContent = `Why: ${result.message}`;
                test.append(why);
            }
            const checks = document.createElement('td');
            checks.className = 'tr-check-summary';
            const info = infoFor(result.nodeid) || {};
            checks.textContent = info.doc || (info.checks && info.checks[0]) || '—';
            checks.title = checks.textContent;
            const file = document.createElement('td');
            file.textContent = findFile(result.nodeid);
            const outcomeCell = document.createElement('td');
            const outcome = document.createElement('span');
            outcome.className = `tr-outcome ${result.outcome}`;
            outcome.textContent = result.outcome;
            outcomeCell.append(outcome);
            const duration = document.createElement('td');
            duration.textContent = `${Number(result.duration || 0).toFixed(2)}s`;
            row.append(test, checks, file, outcomeCell, duration);
            row.tabIndex = 0;
            row.setAttribute('role', 'button');
            row.setAttribute('aria-label', `Show details for ${testTitle(result.nodeid)}`);
            row.addEventListener('click', () => openTestInfo(result.nodeid, result.outcome, result.message));
            row.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    openTestInfo(result.nodeid, result.outcome, result.message);
                }
            });
            body.append(row);
        });
        document.querySelectorAll('#tr-results tr[data-outcome]').forEach((row) => {
            row.hidden = (activeFilter !== 'all' && row.dataset.outcome !== activeFilter);
        });
        const byNode = resultMap();
        tree.querySelectorAll('.tr-test-row').forEach((row) => {
            const result = byNode.get(row.dataset.nodeid);
            const marker = row.querySelector('.tr-test-status');
            if (marker) marker.remove();
            if (result) {
                const status = document.createElement('span');
                status.className = `tr-test-status ${result.outcome}`;
                status.textContent = result.outcome === 'passed' ? '✓' : result.outcome === 'failed' ? '!' : '–';
                row.append(status);
            }
        });
        updateHero(results);
        updateTopicResults();
        updateMapResults(results);
        updateButtons();
    }

    function openTestInfo(nodeid, outcome, message) {
        const details = infoFor(nodeid) || {};
        const result = results.find((item) => item.nodeid === nodeid) || {};
        const finalOutcome = outcome || result.outcome || '';
        const why = message || result.message || '';
        byId('tr-detail-title').textContent = testTitle(nodeid);
        byId('tr-detail-nodeid').textContent = findFile(nodeid);
        const firstAssert = (details.checks || [])[0] || '';
        byId('tr-detail-first-assert').textContent = firstAssert;
        byId('tr-detail-doc').textContent = details.doc || '';
        const outcomeLabel = byId('tr-detail-outcome');
        outcomeLabel.textContent = finalOutcome ? `${finalOutcome}${result.duration ? ` · ${Number(result.duration).toFixed(2)}s` : ''}` : 'Collected test';
        outcomeLabel.className = `tr-detail-outcome ${finalOutcome}`;
        const steps = byId('tr-detail-steps');
        steps.replaceChildren();
        const hasSteps = Boolean(details.setup || details.action || details.expected);
        steps.hidden = !hasSteps || finalOutcome === 'failed';
        if (hasSteps && finalOutcome !== 'failed') {
            [['SETUP', details.setup], ['ACTION', details.action], ['EXPECTED', details.expected]].forEach(([label, value]) => {
                if (!value) return;
                const box = document.createElement('div');
                box.className = 'tr-step';
                const heading = document.createElement('b');
                heading.textContent = label;
                const text = document.createElement('p');
                text.textContent = value;
                box.append(heading, text);
                steps.append(box);
            });
        }
        const checksWrap = byId('tr-detail-checks-wrap');
        const checks = byId('tr-detail-checks');
        checks.replaceChildren();
        checksWrap.hidden = hasSteps && finalOutcome !== 'failed';
        (details.checks || []).forEach((check) => {
            const item = document.createElement('li');
            const code = document.createElement('code');
            code.textContent = check;
            item.append(code);
            checks.append(item);
        });
        if (!checks.childElementCount && !checksWrap.hidden) {
            const item = document.createElement('li');
            item.textContent = details.doc ? 'See the test description above.' : 'No assert statements were found.';
            checks.append(item);
        }
        const whyWrap = byId('tr-detail-why-wrap');
        const failed = finalOutcome === 'failed';
        whyWrap.hidden = !failed;
        byId('tr-detail-expected').textContent = details.expected || 'The expected behavior is described by the test assertions.';
        byId('tr-detail-why').textContent = why || 'The test failed without a failure message.';
        const extra = byId('tr-detail-extra');
        extra.textContent = result.details || byId('tr-output').textContent || 'No additional process output is available.';
        extra.hidden = true;
        byId('tr-detail-show-details').hidden = !failed;
        byId('tr-detail-show-details').textContent = 'Show details';
    }

    function hashNodeId(value) {
        let hash = 2166136261;
        for (let index = 0; index < value.length; index += 1) {
            hash ^= value.charCodeAt(index);
            hash = Math.imul(hash, 16777619);
        }
        return hash >>> 0;
    }

    function hashFraction(value) {
        let hash = value >>> 0;
        hash ^= hash >>> 16;
        hash = Math.imul(hash, 0x7feb352d);
        hash ^= hash >>> 15;
        hash = Math.imul(hash, 0x846ca68b);
        hash ^= hash >>> 16;
        return (hash >>> 0) / 4294967296;
    }

    function positionMapPoints() {
        const centerX = mapWidth / 2;
        const centerY = mapHeight / 2;
        mapPoints.forEach((point) => {
            point.x = centerX + point.dx * mapWidth;
            point.y = centerY + point.dy * mapHeight;
            const radius = Math.hypot(point.x - centerX, point.y - centerY);
            const minDistance = 12;
            if (radius < minDistance) {
                const angle = point.angle;
                point.x = centerX + Math.cos(angle) * minDistance;
                point.y = centerY + Math.sin(angle) * minDistance;
            }
        });
    }

    function makeDotSprite({ color, radius, blur = 0, outline = false, size = 44 }) {
        const scale = 2;
        const canvas = document.createElement('canvas');
        canvas.width = size * scale;
        canvas.height = size * scale;
        const context = canvas.getContext('2d');
        context.scale(scale, scale);
        const center = size / 2;
        context.beginPath();
        context.arc(center, center, radius, 0, Math.PI * 2);
        context.fillStyle = color;
        if (blur) {
            context.shadowColor = color;
            context.shadowBlur = blur;
        }
        context.fill();
        context.shadowBlur = 0;
        if (outline) {
            context.beginPath();
            context.arc(center, center, 7, 0, Math.PI * 2);
            context.strokeStyle = 'rgba(232,241,248,.95)';
            context.lineWidth = 1;
            context.stroke();
        }
        return { canvas, size };
    }

    function createMapSprites() {
        const colors = {
            pending: '#526278',
            passed: '#3dffa0',
            failed: '#ff5f6d',
            skipped: '#9fb0c3',
        };
        const sprites = {};
        Object.entries(colors).forEach(([outcome, color]) => {
            const radius = outcome === 'failed' ? 4.4 : 2.8;
            const blur = outcome === 'failed' ? 12 : outcome === 'passed' ? 3 : 0;
            sprites[outcome] = makeDotSprite({ color, radius, blur });
            sprites[`${outcome}-hover`] = makeDotSprite({ color, radius: 4.5, blur: 14, outline: true });
        });
        return sprites;
    }

    function drawDotsFrame(context, points, sprites, width, height, hoveredPoint) {
        context.clearRect(0, 0, width, height);
        points.forEach((point) => {
            const hovered = point === hoveredPoint;
            const sprite = sprites[`${point.outcome}${hovered ? '-hover' : ''}`] || sprites.pending;
            context.drawImage(sprite.canvas, point.x - sprite.size / 2, point.y - sprite.size / 2, sprite.size, sprite.size);
        });
    }

    function scheduleDotsRedraw() {
        if (dotsRedrawPending) return;
        dotsRedrawPending = true;
        window.requestAnimationFrame(() => {
            dotsRedrawPending = false;
            const canvas = byId('tr-map-dots');
            if (!canvas || !canvas.width || !canvas.height) return;
            mapSprites = mapSprites || createMapSprites();
            drawDotsFrame(canvas.getContext('2d'), mapPoints, mapSprites, mapWidth, mapHeight, hoveredMapPoint);
        });
    }

    function resizeCanvases() {
        const map = byId('tr-map');
        const rect = map.getBoundingClientRect();
        if (!rect.width || !rect.height) return;
        const ratio = Math.max(1, window.devicePixelRatio || 1);
        mapWidth = rect.width;
        mapHeight = rect.height;
        positionMapPoints();
        ['tr-map-lines', 'tr-map-failures', 'tr-map-dots'].forEach((id) => {
            const canvas = byId(id);
            if (!canvas) return;
            canvas.width = Math.round(rect.width * ratio);
            canvas.height = Math.round(rect.height * ratio);
            canvas.getContext('2d').setTransform(ratio, 0, 0, ratio, 0, 0);
        });
        drawMapBase();
        drawFailureRays();
        scheduleDotsRedraw();
    }

    function buildMapPoints() {
        const signature = files.map((file) => `${file.path}:${file.nodeids.join(',')}`).join('|');
        if (signature === mapSignature) return;
        mapSignature = signature;
        mapPoints = [];
        mapPointByNode = new Map();
        const all = files.flatMap((file) => file.selectable ? file.nodeids : []).sort((a, b) => a.localeCompare(b));
        const hashedTests = all.map((nodeid) => ({ nodeid, hash: hashNodeId(nodeid) }))
            .sort((left, right) => left.hash - right.hash || left.nodeid.localeCompare(right.nodeid));
        hashedTests.forEach(({ nodeid, hash }, index) => {
            const angleJitter = (hashFraction(hash ^ 0x9e3779b9) - 0.5) * 0.16;
            const angle = index * 2.399963229728653 + angleJitter;
            const rx = mapWidth * 0.42;
            const ry = mapHeight * 0.38;
            const minRadius = Math.min(0.3, (9 + 3) / Math.max(1, Math.min(rx, ry)));
            const radialNoise = (hashFraction(hash ^ 0xc2b2ae35) - 0.5) * 0.035;
            const radius = Math.max(minRadius, minRadius + (1 - minRadius) * Math.sqrt((index + 0.5) / Math.max(1, hashedTests.length)) + radialNoise);
            const dx = Math.cos(angle) * 0.42 * radius;
            const dy = Math.sin(angle) * 0.38 * radius;
            const point = { nodeid, x: 0, y: 0, dx, dy, angle, outcome: 'pending', message: '' };
            mapPoints.push(point);
            mapPointByNode.set(nodeid, point);
        });
        byId('tr-map-empty').hidden = all.length > 0;
        resizeCanvases();
    }

    function drawMapBase() {
        const canvas = byId('tr-map-lines');
        if (!canvas || !canvas.width) return;
        const context = canvas.getContext('2d');
        context.clearRect(0, 0, mapWidth, mapHeight);
        context.beginPath();
        context.arc(mapWidth / 2, mapHeight / 2, 6, 0, Math.PI * 2);
        context.fillStyle = '#22d3ee';
        context.shadowColor = 'rgba(34,211,238,.8)';
        context.shadowBlur = 14;
        context.fill();
        context.shadowBlur = 0;
        context.strokeStyle = 'rgba(34,211,238,.075)';
        context.lineWidth = .65;
        mapPoints.forEach((point) => {
            context.beginPath();
            context.moveTo(mapWidth / 2, mapHeight / 2);
            context.lineTo(point.x, point.y);
            context.stroke();
        });
    }

    function drawFailureRays() {
        const canvas = byId('tr-map-failures');
        if (!canvas || !canvas.width) return;
        const context = canvas.getContext('2d');
        context.clearRect(0, 0, mapWidth, mapHeight);
        context.strokeStyle = 'rgba(255,95,109,.42)';
        context.lineWidth = 1;
        mapPoints.forEach((point) => {
            if (point.outcome !== 'failed') return;
            context.beginPath();
            context.moveTo(mapWidth / 2, mapHeight / 2);
            context.lineTo(point.x, point.y);
            context.stroke();
        });
    }

    function drawFailureRay(point) {
        const canvas = byId('tr-map-failures');
        if (!canvas || !canvas.width) return;
        const context = canvas.getContext('2d');
        context.strokeStyle = 'rgba(255,95,109,.42)';
        context.lineWidth = 1;
        context.beginPath();
        context.moveTo(mapWidth / 2, mapHeight / 2);
        context.lineTo(point.x, point.y);
        context.stroke();
    }

    function updateMapResults(items) {
        buildMapPoints();
        const incoming = new Map((items || []).map((item) => [item.nodeid, item]));
        const changed = [];
        mapPoints.forEach((point) => {
            const result = incoming.get(point.nodeid);
            const outcome = result ? result.outcome : 'pending';
            const message = result ? result.message || '' : '';
            if (point.outcome !== outcome || point.message !== message) {
                point.outcome = outcome;
                point.message = message;
                changed.push(point);
            }
        });
        const needsRayReset = changed.some((point) => mapResults.get(point.nodeid) === 'failed' && point.outcome !== 'failed');
        if (needsRayReset) drawFailureRays();
        changed.forEach((point) => {
            if (point.outcome === 'failed') drawFailureRay(point);
        });
        if (changed.length) scheduleDotsRedraw();
        mapResults = new Map(mapPoints.map((point) => [point.nodeid, point.outcome]));
    }

    function setMapTip(point, clientX, clientY) {
        const previous = hoveredMapPoint;
        hoveredMapPoint = point;
        if (previous !== point) scheduleDotsRedraw();
        const tip = byId('tr-map-tip');
        tip.replaceChildren();
        if (!point) { tip.hidden = true; return; }
        const heading = document.createElement('strong');
        heading.textContent = point.outcome === 'pending' ? 'Not run' : point.outcome;
        const title = document.createElement('span');
        title.textContent = testTitle(point.nodeid);
        const why = document.createElement('small');
        why.className = 'why';
        if (point.message && ['failed', 'skipped'].includes(point.outcome)) why.textContent = `Why: ${point.message}`;
        tip.append(heading, title);
        if (why.textContent) tip.append(why);
        tip.hidden = false;
        const mapRect = byId('tr-map').getBoundingClientRect();
        const left = Math.max(8, Math.min(mapRect.width - tip.offsetWidth - 8, clientX - mapRect.left + 12));
        const top = Math.max(8, Math.min(mapRect.height - tip.offsetHeight - 8, clientY - mapRect.top + 12));
        tip.style.left = `${left}px`;
        tip.style.top = `${top}px`;
    }

    function pointAtEvent(event) {
        const rect = byId('tr-map-dots').getBoundingClientRect();
        const x = event.clientX - rect.left;
        const y = event.clientY - rect.top;
        let nearest = null;
        let best = 13 * 13;
        mapPoints.forEach((point) => {
            const distance = (point.x - x) ** 2 + (point.y - y) ** 2;
            if (distance < best) { nearest = point; best = distance; }
        });
        return nearest;
    }

    function clearMapForRun() {
        mapPoints.forEach((point) => { point.outcome = 'pending'; point.message = ''; });
        mapResults.clear();
        drawFailureRays();
        scheduleDotsRedraw();
    }

    function appendOutput(lines) {
        if (!lines || !lines.length) return;
        const output = byId('tr-output');
        output.textContent += `${lines.join('\n')}\n`;
        output.scrollTop = output.scrollHeight;
    }

    function parseLiveResults(lines) {
        const found = new Map(results.map((item) => [item.nodeid, item]));
        (lines || []).forEach((line) => {
            const match = line.match(/^(.*?\.py::.+?)\s+(PASSED|FAILED|SKIPPED|ERROR)\b/i);
            if (!match) return;
            const outcome = match[2].toLowerCase() === 'error' ? 'failed' : match[2].toLowerCase();
            found.set(match[1].trim(), { nodeid: match[1].trim(), outcome, duration: 0, message: '' });
        });
        renderBreakdownAndResults([...found.values()]);
    }

    function setRunState(state) {
        const status = state.status || 'empty';
        const badge = byId('tr-run-state');
        badge.textContent = status.replaceAll('_', ' ').toLocaleUpperCase();
        badge.dataset.status = status;
        byId('tr-last-summary').textContent = state.started_at
            ? `${state.mode || 'selected'} run · ${state.started_at}${state.finished_at ? ` · finished ${state.finished_at}` : ''}`
            : `Collection ready · ${files.reduce((sum, file) => sum + (file.selectable ? Number(file.count || 0) : 0), 0)} selectable tests`;
    }

    async function pollRun() {
        try {
            const state = await api(`/api/tests/status?offset=${outputOffset}`);
            outputOffset = state.next_offset || outputOffset;
            mergeInfo(state.info);
            mergeTopics(state.topics);
            appendOutput(state.output);
            if (state.results && state.results.length) renderBreakdownAndResults(state.results);
            else if (state.output && state.output.length) parseLiveResults(state.output);
            lastRun = state.status === 'empty' ? null : (state.results ? state : lastRun || state);
            runActive = ['running', 'starting'].includes(state.status);
            setRunState(state);
            updateHero(results);
            updateButtons();
            if (runActive) pollTimer = window.setTimeout(pollRun, 1000);
        } catch (error) {
            byId('tr-run-state').textContent = error.message;
            runActive = false;
            updateButtons();
        }
    }

    async function pollCollection(refresh) {
        collectionActive = true;
        byId('tr-collection-state').textContent = 'Collecting tests…';
        byId('tr-last-summary').textContent = 'Collecting tests…';
        updateButtons();
        try {
            const state = await api(`/api/tests/collect${refresh ? '?refresh=true' : ''}`);
            if (state.status === 'collecting') {
                window.setTimeout(() => pollCollection(false), 1000);
                return;
            }
            collectionActive = false;
            files = state.files || [];
            mergeInfo(state.info);
            mergeTopics(state.topics);
            renderTree();
            buildMapPoints();
            const failedFiles = files.filter((file) => file.error).length;
            const testCount = files.reduce((sum, file) => sum + (file.selectable ? Number(file.count || 0) : 0), 0);
            if (state.status === 'error' || state.error) {
                const message = state.error || 'Test collection failed';
                byId('tr-collection-state').textContent = `Collection failed: ${message}`;
                byId('tr-last-summary').textContent = `Collection failed: ${message}`;
            } else {
                byId('tr-collection-state').textContent = `${files.length} files · ${testCount} selectable tests${failedFiles ? ` · ${failedFiles} collection error${failedFiles === 1 ? '' : 's'}` : ''}${state.updated_at ? ` · updated ${state.updated_at}` : ''}`;
            }
            if (state.status !== 'error' && !state.error && (!lastRun || lastRun.status === 'empty')) {
                byId('tr-run-caption').textContent = `${testCount} collected tests are ready to run.`;
                byId('tr-total-caption').textContent = `${testCount} collected tests`;
                byId('tr-last-summary').textContent = `${testCount} selectable tests · ${files.length} files`;
            }
            updateHero(results);
        } catch (error) {
            collectionActive = false;
            const message = error.message || 'Test collection request failed';
            byId('tr-collection-state').textContent = `Collection failed: ${message}`;
            byId('tr-last-summary').textContent = `Collection failed: ${message}`;
        }
        updateButtons();
    }

    async function start(mode, targets) {
        if (runActive || collectionActive) return;
        window.clearTimeout(pollTimer);
        outputOffset = 0;
        results = [];
        lastRun = { status: 'running', mode, expected_count: mode === 'selected' ? selectedTestCount() : undefined, results: [] };
        byId('tr-output').textContent = '';
        clearMapForRun();
        renderBreakdownAndResults([]);
        byId('tr-run-state').textContent = 'STARTING';
        byId('tr-run-state').dataset.status = 'starting';
        runActive = true;
        updateButtons();
        try {
            const state = await api('/api/tests/start', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode, targets: targets || [] }),
            });
            lastRun = state;
            mergeInfo(state.info);
            mergeTopics(state.topics);
            setRunState(state);
            pollRun();
        } catch (error) {
            runActive = false;
            lastRun = null;
            byId('tr-run-state').textContent = error.message;
            byId('tr-run-state').dataset.status = 'failed';
            updateButtons();
        }
    }

    function selectMatching() {
        const query = lower(search.value.trim());
        files.filter((file) => file.selectable && (activeTopic === 'all' || file.topic === activeTopic)).forEach((file) => {
            const topicMatch = query && `${topicData(file.topic).name} ${topicData(file.topic).description}`.toLocaleLowerCase().includes(query);
            const fileMatch = !query || topicMatch || lower(file.path).includes(query);
            const matchingNodes = file.nodeids.filter((nodeid) => {
                const info = infoFor(nodeid) || {};
                return !query || topicMatch || fileMatch || lower(`${testTitle(nodeid)} ${info.doc || ''} ${(info.checks || []).join(' ')}`).includes(query);
            });
            if (matchingNodes.length === file.nodeids.length) setFileSelection(file, true);
            else {
                selected.delete(file.path);
                matchingNodes.forEach((nodeid) => selected.add(nodeid));
            }
        });
        updateButtons();
    }

    byId('tr-refresh').addEventListener('click', () => pollCollection(true));
    byId('tr-select-matching').addEventListener('click', selectMatching);
    byId('tr-clear').addEventListener('click', () => { selected.clear(); updateButtons(); });
    search.addEventListener('input', applyTreeFilter);
    byId('tr-run-all').addEventListener('click', () => start('all'));
    byId('tr-run-selected').addEventListener('click', () => start('selected', [...selected]));
    byId('tr-run-failed').addEventListener('click', () => start('failed'));
    byId('tr-cancel').addEventListener('click', async () => {
        try { await api('/api/tests/cancel', { method: 'POST' }); await pollRun(); } catch (error) { byId('tr-run-state').textContent = error.message; }
    });
    resultFilters.forEach((button) => button.addEventListener('click', () => {
        activeFilter = button.dataset.resultFilter;
        resultFilters.forEach((item) => item.setAttribute('aria-pressed', String(item === button)));
        document.querySelectorAll('#tr-results tr[data-outcome]').forEach((row) => { row.hidden = activeFilter !== 'all' && row.dataset.outcome !== activeFilter; });
    }));
    byId('tr-detail-show-details').addEventListener('click', () => {
        const details = byId('tr-detail-extra');
        details.hidden = !details.hidden;
        byId('tr-detail-show-details').textContent = details.hidden ? 'Show details' : 'Hide details';
    });
    byId('tr-map-dots').addEventListener('mousemove', (event) => {
        const point = pointAtEvent(event);
        if (point !== hoveredMapPoint) setMapTip(point, event.clientX, event.clientY);
        else if (point) {
            const tip = byId('tr-map-tip');
            const rect = byId('tr-map').getBoundingClientRect();
            tip.style.left = `${Math.max(8, Math.min(rect.width - tip.offsetWidth - 8, event.clientX - rect.left + 12))}px`;
            tip.style.top = `${Math.max(8, Math.min(rect.height - tip.offsetHeight - 8, event.clientY - rect.top + 12))}px`;
        }
    });
    byId('tr-map-dots').addEventListener('mouseleave', () => setMapTip(null, 0, 0));
    byId('tr-map-dots').addEventListener('click', (event) => {
        const point = pointAtEvent(event);
        if (point) openTestInfo(point.nodeid, point.outcome, point.message);
    });
    byId('tr-map-dots').addEventListener('keydown', (event) => {
        if (!mapPoints.length) return;
        if (event.key === 'ArrowRight' || event.key === 'ArrowDown') focusedMapIndex = (focusedMapIndex + 1) % mapPoints.length;
        else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') focusedMapIndex = (focusedMapIndex - 1 + mapPoints.length) % mapPoints.length;
        else if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            const point = mapPoints[focusedMapIndex];
            if (point) openTestInfo(point.nodeid, point.outcome, point.message);
            return;
        } else return;
        event.preventDefault();
        const point = mapPoints[focusedMapIndex];
        const rect = byId('tr-map-dots').getBoundingClientRect();
        setMapTip(point, rect.left + point.x * rect.width / mapWidth, rect.top + point.y * rect.height / mapHeight);
    });
    window.addEventListener('resize', resizeCanvases);
    if ('ResizeObserver' in window) {
        mapResizeObserver = new ResizeObserver(resizeCanvases);
        mapResizeObserver.observe(byId('tr-map'));
    }
    byId('tr-map-dots').addEventListener('focus', () => { if (!mapPoints.length) return; const point = mapPoints[focusedMapIndex]; const rect = byId('tr-map-dots').getBoundingClientRect(); setMapTip(point, rect.left + point.x * rect.width / mapWidth, rect.top + point.y * rect.height / mapHeight); });
    Promise.all([pollCollection(false), pollRun()]);
})();
