(function () {
    'use strict';

    function loadStatus() {
        fetch('/api/settings/gmail/status')
            .then(function (response) {
                if (!response.ok) throw new Error('HTTP ' + response.status);
                return response.json();
            })
            .then(function (data) {
                var linked = data.linked === true;
                document.getElementById('gmailStatusLabel').textContent = data.revoked
                    ? 'Revoked'
                    : (linked ? 'Connected' : 'Not connected');
                document.getElementById('gmailAccount').textContent = linked
                    ? (data.google_email || 'Connected account')
                    : 'Not connected';
                document.getElementById('gmailScopes').textContent = linked
                    && data.granted_scopes && data.granted_scopes.length
                    ? data.granted_scopes.join(', ')
                    : '—';
                document.getElementById('gmailLastRefresh').textContent = data.last_refresh_at || '—';
                document.getElementById('gmailConnect').style.display = linked ? 'none' : '';
                document.getElementById('gmailDisconnect').style.display = linked ? '' : 'none';
            })
            .catch(function (error) {
                var message = document.getElementById('gmailError');
                message.textContent = 'Unable to load Gmail status: ' + error.message;
                message.style.display = '';
                document.getElementById('gmailStatusLabel').textContent = 'Unavailable';
            });
    }

    function connectGmail() {
        window.location.href = '/api/settings/gmail/connect';
    }

    function disconnectGmail() {
        fetch('/api/settings/gmail', { method: 'DELETE' })
            .then(function (response) {
                if (!response.ok) throw new Error('HTTP ' + response.status);
                return response.json();
            })
            .then(loadStatus)
            .catch(function (error) {
                var message = document.getElementById('gmailError');
                message.textContent = 'Disconnect failed: ' + error.message;
                message.style.display = '';
            });
    }

    function init() {
        document.getElementById('gmailConnect').addEventListener('click', connectGmail);
        document.getElementById('gmailDisconnect').addEventListener('click', disconnectGmail);
        var params = new URLSearchParams(window.location.search);
        if (params.get('gmail') === 'error') {
            var messages = {
                configuration: 'Gmail connection is not configured. Contact an administrator.',
                consent_denied: 'Google authorization was cancelled.',
                invalid_code: 'Google did not return an authorization code. Try again.',
                state_missing: 'The Gmail authorization response was incomplete. Try again.',
                state_invalid: 'The Gmail authorization expired or could not be verified. Try again.',
                start_failed: 'Could not start Gmail authorization. Try again.',
                exchange_failed: 'Gmail authorization failed. Try again.'
            };
            var message = document.getElementById('gmailError');
            message.textContent = messages[params.get('reason')] || 'Gmail authorization failed. Try again.';
            message.style.display = '';
        }
        if (params.has('gmail')) {
            history.replaceState(null, '', window.location.pathname);
        }
        loadStatus();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
}());
