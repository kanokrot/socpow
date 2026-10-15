(function () {
    'use strict';

    var SOURCE_LABELS = {
        virustotal: 'VirusTotal',
        abuseipdb: 'AbuseIPDB',
        otx: 'AlienVault OTX'
    };
    var SOURCE_NOTES = {
        virustotal: '500 requests / day',
        abuseipdb: '1,000 requests / day',
        otx: 'Unlimited'
    };

    function byId(id) { return document.getElementById(id); }

    function showError() {
        var node = byId('userApiKeysError');
        if (!node) return;
        node.textContent = 'Could not update personal API keys. Please try again.';
        node.style.display = '';
    }

    function clearError() {
        var node = byId('userApiKeysError');
        if (node) {
            node.textContent = '';
            node.style.display = 'none';
        }
    }

    function setStatus(text) {
        var node = byId('userApiKeysStatus');
        if (node) node.textContent = text || '';
    }

    function make(tag, className, text) {
        var node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }

    async function request(url, options) {
        var response = await fetch(url, options || { credentials: 'include' });
        if (!response.ok) throw new Error('request failed');
        return response.status === 204 ? null : response.json();
    }

    function sourceLabel(source) {
        if (source.label) return source.label;
        if (SOURCE_LABELS[source.source]) return SOURCE_LABELS[source.source];
        return String(source.source || '').replace(/[_-]+/g, ' ').replace(/\b\w/g, function (letter) {
            return letter.toUpperCase();
        });
    }

    function renderRow(source) {
        var configured = source.configured === true;
        var labelText = sourceLabel(source);
        var row = make('div', 'user-api-key-row');
        var identity = make('div', 'user-api-key-identity');
        var dot = make('span', 'user-api-key-dot ' + (configured ? 'is-configured' : 'is-not-set'));
        dot.setAttribute('aria-label', configured ? 'Configured' : 'Not set');
        dot.title = configured ? 'Configured' : 'Not set';
        identity.appendChild(dot);

        var description = make('div', 'user-api-key-description');
        description.appendChild(make('div', 'fw-semibold', labelText));
        var note = source.note || SOURCE_NOTES[source.source];
        if (note) description.appendChild(make('div', 'small text-muted', note));
        if (configured) {
            var suffix = String(source.masked_suffix || '').slice(-4);
            if (suffix) description.appendChild(make('div', 'small font-monospace text-muted mt-1', suffix));
        }
        identity.appendChild(description);
        row.appendChild(identity);

        var controls = make('div', 'user-api-key-controls');
        if (configured) {
            var remove = make('button', 'btn btn-outline-danger btn-sm', 'Remove');
            remove.type = 'button';
            remove.addEventListener('click', function () { removeKey(source); });
            controls.appendChild(remove);
        } else {
            var input = make('input', 'form-control form-control-sm font-monospace');
            input.type = 'password';
            input.autocomplete = 'new-password';
            input.maxLength = 4096;
            input.placeholder = 'Enter API key';
            input.setAttribute('aria-label', labelText + ' API key');
            input.addEventListener('keydown', function (event) {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    saveKey(source, input);
                }
            });
            var save = make('button', 'btn btn-accent btn-sm', 'Save');
            save.type = 'button';
            save.addEventListener('click', function () { saveKey(source, input); });
            controls.appendChild(input);
            controls.appendChild(save);
        }
        row.appendChild(controls);
        return row;
    }

    function render(sources) {
        var container = byId('userApiKeysRows');
        var rows = Array.isArray(sources) ? sources : [];
        container.replaceChildren();
        rows.forEach(function (source) { container.appendChild(renderRow(source)); });
        if (!rows.length) container.appendChild(make('div', 'text-muted small', 'No API key sources are available.'));
    }

    async function refresh() {
        clearError();
        var container = byId('userApiKeysRows');
        if (!container) return;
        try {
            var payload = await request('/api/account/intel-keys', { credentials: 'include' });
            var disabled = byId('userApiKeysDisabled');
            if (payload && payload.enabled === false) {
                disabled.style.display = '';
                container.style.display = 'none';
                setStatus('');
                return;
            }
            disabled.style.display = 'none';
            container.style.display = '';
            render(payload && payload.keys);
        } catch (error) {
            container.replaceChildren();
            showError();
        }
    }

    async function saveKey(source, input) {
        clearError();
        setStatus('');
        var apiKey = input.value;
        if (!apiKey.trim()) return;
        try {
            await request('/api/account/intel-keys/' + encodeURIComponent(source.source), {
                method: 'PUT',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ api_key: apiKey })
            });
            apiKey = '';
            input.value = '';
            setStatus('Key saved.');
            await refresh();
        } catch (error) {
            showError();
        }
    }

    async function removeKey(source) {
        clearError();
        setStatus('');
        try {
            await request('/api/account/intel-keys/' + encodeURIComponent(source.source), {
                method: 'DELETE', credentials: 'include'
            });
            setStatus('Key removed.');
            await refresh();
        } catch (error) {
            showError();
        }
    }

    function init() {
        if (byId('userApiKeysRows')) refresh();
    }
    window.AccountApiKeys = { init: init };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
}());
