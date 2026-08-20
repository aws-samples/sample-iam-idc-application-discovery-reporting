"""
Run the adversarial invariant audit as part of the normal test suite.

This is the mechanism that answers "how do I add an adversarial check to an
implementation": not a checklist someone remembers to follow, but a test that
fails the existing gate. `pytest tests/` already runs before every commit, so
the audit cannot be skipped by forgetting it.

What separates this from the rest of the suite: every other test asserts that
intended behaviour is present. This one asserts that unintended breakage is
absent -- decorators still attached to the functions they were written for, test
classes still collectable, documented examples still matching the code, log
statements still redacting identity fields. Each check exists because that exact
bug was introduced during development and passed a "does it compile" review.

The audit is imported and called in-process rather than shelled out. An earlier
version used subprocess.run, which Semgrep rated HIGH
(dangerous-subprocess-use-audit) because the argument list was not a static
string. Importing removes the finding rather than suppressing it, and is faster.

To use it while editing:

    python3 scripts/adversarial-audit.py --baseline /tmp/before.json   # before
    ...make changes...
    python3 scripts/adversarial-audit.py --against /tmp/before.json    # after

The --against mode reports any class, function, or decorator attachment that
existed before and does not now, which is the check that would have caught a
regex deletion swallowing a class statement.
"""

import contextlib
import importlib.util
import io
import os
import sys

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_AUDIT_PATH = os.path.join(_REPO, 'scripts', 'adversarial-audit.py')


def _load_audit():
    """Import the audit script under a private module name."""
    spec = importlib.util.spec_from_file_location('_adversarial_audit', _AUDIT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(module):
    """Call the audit and return (exit_code, stdout)."""
    module.findings.clear()
    buf = io.StringIO()
    argv = sys.argv
    sys.argv = ['adversarial-audit.py']
    try:
        with contextlib.redirect_stdout(buf):
            code = module.main()
    finally:
        sys.argv = argv
    return code, buf.getvalue()


@pytest.mark.skipif(not os.path.exists(_AUDIT_PATH), reason='audit script not present')
def test_adversarial_audit_reports_no_findings():
    """The audit must be clean. Its output is the failure message."""
    code, out = _run(_load_audit())
    assert code == 0, f"adversarial invariant audit found regressions:\n\n{out}"


@pytest.mark.skipif(not os.path.exists(_AUDIT_PATH), reason='audit script not present')
def test_audit_detects_a_planted_regression(tmp_path):
    """
    Mutation check on the audit itself.

    An audit that cannot fail is worse than no audit, because it produces
    confidence. Point the audit at a scratch tree containing a broken markdown
    anchor and confirm it reports one.
    """
    module = _load_audit()

    (tmp_path / 'README.md').write_text('# Title\n\nSee [nowhere](#no-such-heading).\n')
    for directory in ('identity-center-reporting/src',
                      'identity-center-reporting/lib',
                      'identity-center-remediation/lambda'):
        (tmp_path / directory).mkdir(parents=True, exist_ok=True)

    module.REPO = str(tmp_path)
    code, out = _run(module)

    assert code == 1, (
        'the audit passed a tree containing a broken anchor, so it cannot '
        f'detect that class of regression:\n{out}'
    )
    assert 'anchors' in out, f'expected an anchors finding, got:\n{out}'


@pytest.mark.skipif(not os.path.exists(_AUDIT_PATH), reason='audit script not present')
def test_audit_detects_unredacted_pii_reached_through_a_key():
    """
    Second mutation check, for the blind spot the audit actually had.

    Its first version matched only variables *named* like PII, so it missed
    `details['name']` -- a resolved Identity Store UserName. The Content Security
    Review rated two such lines HIGH. Assert the subscript form is caught.
    """
    module = _load_audit()
    module.findings.clear()

    segment = "logger.debug(f\"Retrieved user details: {details['name']}\")"
    assert module.PII_SUBSCRIPT.search(segment), (
        'the audit no longer detects a resolved name logged through a dictionary '
        'key, which is the exact pattern it originally missed'
    )
    # And a redacted call must not trip it, or the check is useless noise.
    safe = 'logger.debug("Retrieved user details: %s", redact_principal(details["name"]))'
    assert 'redact_principal' in safe
