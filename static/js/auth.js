/**
 * SOCPOW browser authentication helpers.
 *
 * Browser authentication is cookie-only: the login response deliberately does
 * not expose the session token to JavaScript.  This module supplies CSRF
 * headers from the readable double-submit cookie and keeps API failures on
 * protected pages routed back through the login screen.
 */
(function () {
    'use strict';

    var SESSION_PATHS = ['/login', '/register', '/accept-invite'];
    var UNSAFE_METHODS = { POST: true, PUT: true, PATCH: true, DELETE: true };
    var redirecting = false;

    function safeNext(value) {
        var candidate = typeof value === 'string' && value ? value : '/';
        if (candidate.charAt(0) !== '/' || candidate.indexOf('//') === 0 || candidate.indexOf('\\') !== -1) {
            return '/';
        }
        try {
            var url = new URL(candidate, window.location.origin);
            if (url.origin !== window.location.origin) return '/';
            return candidate;
        } catch (error) {
            return '/';
        }
    }

    function getCookie(name) {
        var prefix = name + '=';
        var cookies = document.cookie ? document.cookie.split(';') : [];
        for (var i = 0; i < cookies.length; i += 1) {
            var cookie = cookies[i].trim();
            if (cookie.indexOf(prefix) === 0) {
                return decodeURIComponent(cookie.slice(prefix.length));
            }
        }
        return '';
    }

    function getCompatibleCookie(names) {
        for (var i = 0; i < names.length; i += 1) {
            var value = getCookie(names[i]);
            if (value) return value;
        }
        return '';
    }

    function showToast(message, type) {
        var container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + (type || 'info');
        toast.setAttribute('role', 'status');
        toast.textContent = message;
        container.appendChild(toast);
        window.setTimeout(function () {
            toast.style.opacity = '0';
            window.setTimeout(function () {
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }, 4200);
    }

    function isAuthPage() {
        return SESSION_PATHS.indexOf(window.location.pathname) !== -1;
    }

    function redirectToLogin() {
        if (redirecting || isAuthPage()) return;
        redirecting = true;
        var next = safeNext(window.location.pathname + window.location.search);
        window.location.assign('/login?next=' + encodeURIComponent(next));
    }

    function isSameOrigin(url) {
        return url.origin === window.location.origin;
    }

    function fetchWithAuth(input, init) {
        var options = Object.assign({}, init || {});
        var requestUrl = typeof input === 'string' ? input : input.url;
        var url = new URL(requestUrl, window.location.origin);
        var method = String(options.method || (input && input.method) || 'GET').toUpperCase();
        var sourceHeaders = input instanceof Request && !options.headers ? input.headers : undefined;
        var headers = new Headers(options.headers || sourceHeaders || {});

        if (isSameOrigin(url)) {
            options.credentials = options.credentials || 'include';
            if (UNSAFE_METHODS[method]) {
                var csrf = getCompatibleCookie(['socpow_csrf', 'cabta_csrf']);
                if (csrf) headers.set('X-CSRF-Token', csrf);
            }
        }
        options.headers = headers;

        return window.__socpowNativeFetch(input, options).then(function (response) {
            if (response.status === 401 && !isAuthPage()) {
                redirectToLogin();
            }
            return response;
        });
    }

    if (!window.__socpowNativeFetch) {
        window.__socpowNativeFetch = window.fetch.bind(window);
        window.fetch = fetchWithAuth;
    }

    function responseMessage(response, fallback) {
        return response.clone().json().then(function (data) {
            return data.detail || data.error || fallback;
        }).catch(function () {
            return fallback;
        });
    }

    function setFormError(element, message) {
        if (!element) return;
        element.textContent = message;
        element.classList.remove('d-none');
    }

    function clearFormError(element) {
        if (!element) return;
        element.textContent = '';
        element.classList.add('d-none');
    }

    function bindLoginForm(form) {
        form.addEventListener('submit', function (event) {
            event.preventDefault();
            var errorElement = document.getElementById('login-error');
            clearFormError(errorElement);
            var identifier = document.getElementById('login-identifier').value.trim();
            var password = document.getElementById('login-password').value;
            if (!identifier || !password) {
                setFormError(errorElement, 'Enter your username/email and password.');
                return;
            }

            var button = form.querySelector('button[type="submit"]');
            if (button) button.disabled = true;
            fetch('/api/auth/login', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: identifier, password: password })
            }).then(function (response) {
                if (!response.ok) {
                    return responseMessage(response, response.status === 429
                        ? 'Too many login attempts. Try again later.'
                        : 'Invalid username/email or password.').then(function (message) {
                            throw new Error(message);
                        });
                }
                return response.json();
            }).then(function (data) {
                var nextPath = form.getAttribute('data-next');
                if (nextPath === '/') {
                    nextPath = data.default_redirect || nextPath;
                }
                window.location.assign(safeNext(nextPath));
            }).catch(function (error) {
                setFormError(errorElement, error.message || 'Sign in failed.');
                showToast(error.message || 'Sign in failed.', 'error');
            }).finally(function () {
                if (button) button.disabled = false;
            });
        });
    }

    function bindRegisterForm(form) {
        form.addEventListener('submit', function (event) {
            event.preventDefault();
            var errorElement = document.getElementById('register-error');
            clearFormError(errorElement);
            var token = document.getElementById('invite-token').value.trim();
            var username = document.getElementById('register-username').value.trim();
            var password = document.getElementById('register-password').value;
            var confirmation = document.getElementById('register-password-confirm').value;
            if (!token || !username || !password) {
                setFormError(errorElement, 'Complete all required fields.');
                return;
            }
            if (password !== confirmation) {
                setFormError(errorElement, 'Passwords do not match.');
                return;
            }

            var button = form.querySelector('button[type="submit"]');
            if (button) button.disabled = true;
            fetch('/api/auth/accept-invite', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: token, username: username, password: password })
            }).then(function (response) {
                if (!response.ok) {
                    return responseMessage(response, 'Account activation failed.').then(function (message) {
                        throw new Error(message);
                    });
                }
                return response.json();
            }).then(function () {
                showToast('Account activated. Sign in to continue.', 'success');
                window.setTimeout(function () { window.location.assign('/login'); }, 500);
            }).catch(function (error) {
                setFormError(errorElement, error.message || 'Account activation failed.');
                showToast(error.message || 'Account activation failed.', 'error');
            }).finally(function () {
                if (button) button.disabled = false;
            });
        });
    }

    function bindLogoutButton(button) {
        button.addEventListener('click', function () {
            button.disabled = true;
            fetch('/api/auth/logout', {
                method: 'POST',
                credentials: 'include'
            }).then(function (response) {
                if (!response.ok) {
                    return responseMessage(response, 'Logout failed. Please try again.').then(function (message) {
                        throw new Error(message);
                    });
                }
                window.location.assign('/login');
            }).catch(function (error) {
                showToast(error.message || 'Logout failed. Please try again.', 'error');
                button.disabled = false;
            });
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        var loginForm = document.querySelector('[data-auth-form="login"]');
        var registerForm = document.querySelector('[data-auth-form="register"]');
        var logoutButton = document.getElementById('logout-button');
        if (loginForm) bindLoginForm(loginForm);
        if (registerForm) bindRegisterForm(registerForm);
        if (logoutButton) bindLogoutButton(logoutButton);
    });

    window.SOCPOWAuth = {
        fetch: fetchWithAuth,
        getCookie: getCookie,
        safeNext: safeNext,
        showToast: showToast,
        redirectToLogin: redirectToLogin
    };
    window.showToast = window.showToast || showToast;
}());
