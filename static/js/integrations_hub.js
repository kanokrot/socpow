(function () {
    'use strict';

    function byId(id) { return document.getElementById(id); }
    function setText(id, text) {
        var element = byId(id);
        if (element) element.textContent = text;
    }

    function renderProviderSummary(elementId, providers, includeUnavailable) {
        var summary = byId(elementId);
        if (!summary) return;
        var rows = providers || [];
        var configured = rows.filter(function (item) { return item.configured === true; });
        var needsSetup = rows.filter(function (item) { return item.configured === false; });
        var unavailable = rows.filter(function (item) { return item.configured === null; });
        var lines = [
            'Configured: ' + (configured.map(function (item) { return item.name; }).join(', ') || 'None'),
            'Needs setup: ' + (needsSetup.map(function (item) { return item.name; }).join(', ') || 'None')
        ];
        if (includeUnavailable && unavailable.length) {
            lines.push('Status unavailable: ' + unavailable.map(function (item) { return item.name; }).join(', '));
        }

        summary.replaceChildren();
        lines.forEach(function (line) {
            var paragraph = document.createElement('p');
            paragraph.textContent = line;
            summary.appendChild(paragraph);
        });
    }

    function renderCount(id, items) {
        var rows = items || [];
        var measurable = rows.filter(function (item) { return item.configured !== null; });
        var configured = measurable.filter(function (item) { return item.configured === true; }).length;
        setText(id, configured + ' of ' + measurable.length + ' configured');
    }

    function showSummaryUnavailable(elementId) {
        var summary = byId(elementId);
        if (!summary) return;
        var paragraph = document.createElement('p');
        paragraph.textContent = 'Status unavailable';
        summary.replaceChildren(paragraph);
    }

    fetch('/api/integrations/status', { credentials: 'same-origin' })
        .then(function (response) {
            if (!response.ok) throw new Error('status unavailable');
            return response.json();
        })
        .then(function (data) {
            renderCount('hubThreatCount', data.threat_intel);
            renderProviderSummary('hubThreatSummary', data.threat_intel, true);
            renderCount('hubSandboxCount', data.sandboxes);
            renderProviderSummary('hubSandboxSummary', data.sandboxes, false);

            var mcp = data.mcp || {};
            var mcpText = String(mcp.configured_count) + ' configured';
            if (Number.isInteger(mcp.connected_count)) mcpText += ' · ' + mcp.connected_count + ' connected';
            setText('hubMcpCount', mcpText);
        })
        .catch(function () {
            setText('hubThreatCount', 'Status unavailable');
            setText('hubSandboxCount', 'Status unavailable');
            setText('hubMcpCount', 'Status unavailable');
            showSummaryUnavailable('hubThreatSummary');
            showSummaryUnavailable('hubSandboxSummary');
        });

}());
