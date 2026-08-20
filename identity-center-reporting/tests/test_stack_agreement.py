"""
The two stacks must reach the same verdict about the same assignment.

The documented workflow is to deploy reporting, establish a baseline from its
reports, and only then enable the monitoring stack's enforcement. That is only sound
if both stacks judge an assignment identically. They did not: reporting accepted a
GroupNameRegex parameter, shipped it to three Lambdas as GROUP_NAME_REGEX, and never
read it -- so with a regex configured, monitoring judged the extracted friendly name
while reporting judged the raw group name. Nothing caught it because each stack's
tests only ever exercised its own matcher.

These tests compare the two implementations directly, which is the only assertion
that can catch a divergence in either one.
"""

import contextlib
import importlib.util
import os
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORTING = REPO_ROOT / 'identity-center-reporting'
MONITORING = REPO_ROOT / 'identity-center-remediation' / 'lambda'


@contextlib.contextmanager
def _temporarily_on_syspath(paths):
    """
    Add paths to sys.path for the duration of an import, then remove them.

    These modules need their package roots importable, but leaving the entries in
    place changes how *other* test modules resolve `matching` and `shared` for the
    rest of the session. This file loads matching.py under a second module name, so
    a permanent path change means two live copies of the same module with separate
    globals -- and an unrelated property test in test_csv_matching failed once in a
    full run because of it. Scope the mutation to the import.
    """
    added = [str(p) for p in paths if str(p) not in sys.path]
    for entry in added:
        sys.path.insert(0, entry)
    try:
        yield
    finally:
        for entry in added:
            try:
                sys.path.remove(entry)
            except ValueError:
                pass


def _load(path, name, extra_syspath=()):
    """Load a module by file path, without importing its package or leaking state."""
    with _temporarily_on_syspath(extra_syspath):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    # Do not leave the private alias in sys.modules; test_csv_matching imports the
    # real `matching`, and a stray second entry invites the wrong one being found.
    sys.modules.pop(name, None)
    return module


@pytest.fixture(scope='module')
def matchers():
    """The reporting matcher and the monitoring validator, both real."""
    monitoring = _load(MONITORING / 'validation.py', '_mon_validation', (MONITORING,))

    # matching.py imports shared.utils; give it the reporting src root.
    reporting = _load(
        REPORTING / 'src' / 'lambdas' / 'assignment-discovery' / 'matching.py',
        '_rep_matching',
        (REPORTING / 'src' / 'lambdas',),
    )
    return reporting, monitoring


# (application_name, group_name, regex_or_None)
CASES = [
    # No regex -- the plain cases both stacks always agreed on.
    ('sagemaker_readonly', 'ReadOnly', None),
    ('sagemaker_readonly', 'Developer', None),
    ('sagemaker_readonly', 'read', None),
    ('sagemaker_readonly', 'only', None),
    ('sagemaker_readonly', 'a', None),
    ('CustomerPortal', 'CustomerPortal-Admins', None),
    ('MyApp-DEVS', 'devs', None),

    # With a regex -- where the two stacks used to disagree. The blog's own naming
    # convention (AWS_<acct>_<Service>_<LOB>_<ENV>_<AppName>) needs one of these,
    # so this is the configuration a reader is most likely to land on.
    ('Finance_PROD', 'AWS-Finance-Admins', 'AWS-([^-]+)-'),
    ('CustomerPortal', 'AWS-C-Admins', 'AWS-([^-]+)-'),
    ('SageMaker_Data_PROD_GTLabel', 'AWS_123412341234_SageMaker_Data_PROD_GTLabel',
     r'AWS_\d+_(.+)'),
    ('GTLabel', 'AWS_123412341234_SageMaker_Data_PROD_GTLabel', r'.*_([^_]+)$'),

    # Regex fallback paths: an optional group that did not participate, a group that
    # matched zero characters, a pattern that matches nothing, and an invalid pattern.
    # Each must fall back to the full group name on BOTH sides.
    ('CustomerPortal', 'CustomerPortal-Admins', '^(ADFS-)?'),
    ('CustomerPortal', 'CustomerPortal-Admins', '^([A-Z]*)'),
    ('CustomerPortal', 'CustomerPortal-Admins', 'NoMatchHere-([^-]+)'),
    ('CustomerPortal', 'CustomerPortal-Admins', '([unclosed'),
]


@pytest.mark.parametrize('app,group,regex', CASES)
def test_both_stacks_agree(matchers, app, group, regex):
    reporting, monitoring = matchers

    reporting_verdict = reporting.evaluate_group_application_match(
        principal_type='GROUP',
        principal_name=group,
        application_name=app,
        group_name_regex=regex,
    ) == 'Yes'

    monitoring_verdict = monitoring.validate_assignment(app, group, regex).is_compliant

    assert reporting_verdict == monitoring_verdict, (
        f"stacks disagree on app={app!r} group={group!r} regex={regex!r}: "
        f"reporting={'COMPLIANT' if reporting_verdict else 'NON-COMPLIANT'}, "
        f"monitoring={'COMPLIANT' if monitoring_verdict else 'NON-COMPLIANT'}"
    )


def test_regex_actually_changes_the_reporting_verdict(matchers):
    """
    Guard against the regex being accepted and ignored again.

    Without this, reporting could revert to discarding group_name_regex and
    test_both_stacks_agree would still pass for every case where the extraction
    happens not to alter the outcome.
    """
    reporting, _ = matchers
    app, group, regex = 'Finance_PROD', 'AWS-Finance-Admins', 'AWS-([^-]+)-'

    without = reporting.evaluate_group_application_match(
        principal_type='GROUP', principal_name=group, application_name=app)
    with_regex = reporting.evaluate_group_application_match(
        principal_type='GROUP', principal_name=group, application_name=app,
        group_name_regex=regex)

    assert without == 'No'
    assert with_regex == 'Yes'


def test_group_name_regex_env_var_is_consumed():
    """
    The stack sets GROUP_NAME_REGEX on the Lambdas; some code must read it.

    It was set on three functions and read by none. An environment variable that
    nothing reads is a parameter that silently does nothing, and the deploy still
    succeeds -- so only a test that greps for the read can catch it.
    """
    # Require an actual environment read, not the mere presence of the name.
    #
    # The first version of this test searched for the string "GROUP_NAME_REGEX"
    # anywhere under src/, and passed on a docstring in matching.py that merely
    # explains the variable -- so deleting the caller's read left it green. Prose
    # about a value is not a read of it.
    reader = re.compile(
        r"""os\.environ(?:\.get)?[\(\[]\s*['"]GROUP_NAME_REGEX['"]"""
    )
    src = REPORTING / 'src'
    readers = [
        p.relative_to(REPORTING)
        for p in src.rglob('*.py')
        if reader.search(p.read_text(errors='ignore'))
    ]
    assert readers, (
        "no file under src/ reads GROUP_NAME_REGEX from the environment, but the "
        "stack sets it on the assignment-discovery, csv-export and access-tracker "
        "functions -- a parameter that is shipped and never read silently does nothing"
    )


def test_principal_name_is_not_written_to_xray_metadata():
    """
    X-Ray metadata is a durable store read separately from the logs.

    Every log statement in matching.py redacts the principal; the subsegment
    metadata wrote it verbatim, which put it straight back.
    """
    text = (REPORTING / 'src' / 'lambdas' / 'assignment-discovery' / 'matching.py').read_text()
    offenders = [
        line.strip() for line in text.splitlines()
        if "'principal_name':" in line or '"principal_name":' in line
    ]
    assert not offenders, (
        "principal_name is written into an X-Ray payload:\n" + "\n".join(offenders)
    )
