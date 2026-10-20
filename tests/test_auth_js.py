from __future__ import annotations

import json
import subprocess
from pathlib import Path


def test_fetch_interceptor_redirects_401_but_not_403() -> None:
    auth_js = Path(__file__).parents[1] / "static" / "js" / "auth.js"
    harness = r"""
const fs = require('fs');
const vm = require('vm');

const redirects = [];
const nativeFetch = (input) => Promise.resolve({status: Number(input), ok: false});

class Headers {
    constructor(values) { this.values = values || {}; }
    set(name, value) { this.values[name] = value; }
}

const window = {
    location: {
        origin: 'http://socpow.test',
        pathname: '/dashboard',
        search: '',
        assign: (value) => redirects.push(value),
    },
    fetch: nativeFetch,
    setTimeout: () => 0,
};

const document = {
    cookie: '',
    addEventListener: () => {},
    getElementById: () => null,
    querySelector: () => null,
    body: {},
};

const context = {
    window,
    document,
    URL,
    Headers,
    Request: class Request {},
    setTimeout: () => 0,
};

vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);

window.SOCPOWAuth.fetch('401')
    .then(() => window.SOCPOWAuth.fetch('403'))
    .then(() => {
        if (redirects.length !== 1 || redirects[0] !== '/login?next=%2Fdashboard') {
            throw new Error(JSON.stringify(redirects));
        }
    });
"""

    result = subprocess.run(
        ["node", "-e", harness, str(auth_js)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, json.dumps(
        {"stdout": result.stdout, "stderr": result.stderr}
    )
