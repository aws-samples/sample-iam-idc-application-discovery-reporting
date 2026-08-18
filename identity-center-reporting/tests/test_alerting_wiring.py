"""
Regression tests for SNS alerting wiring.

shared/alerting.py resolves an SNS topic from the environment and routes by
severity. When the topic ARN is absent, send_alert() logs "No topic configured"
and returns False, so the alert is dropped rather than delivered. That failure is
silent: nothing raises, and a run that could not report its own failure still
looks healthy.

These tests assert that every Lambda with alerting call sites receives all four
topic ARNs and can publish to them.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = REPO_ROOT / "cdk.out" / "IamIdentityCenterDiscoveryStack-dev.template.json"

# Env vars read by AlertManager.__init__ in src/lambdas/shared/alerting.py
REQUIRED_TOPIC_VARS = {
    "CRITICAL_ALERTS_TOPIC_ARN",
    "WARNING_ALERTS_TOPIC_ARN",
    "ACCESS_ISSUES_TOPIC_ARN",
    "DISCOVERY_STATUS_TOPIC_ARN",
}

# Lambdas that import shared.alerting or call its helpers
ALERTING_FUNCTIONS = (
    "iam-identity-center-instance-scanner",
    "iam-identity-center-change-detection",
)


def _load_template():
    if not TEMPLATE.exists():
        pytest.skip(
            f"{TEMPLATE.name} not found -- run 'cdk synth' before this test"
        )
    return json.loads(TEMPLATE.read_text())


def _lambda_resources(template):
    out = {}
    for resource in template.get("Resources", {}).values():
        if resource.get("Type") != "AWS::Lambda::Function":
            continue
        name = resource.get("Properties", {}).get("FunctionName")
        if isinstance(name, str):
            out[name] = resource
    return out


@pytest.mark.parametrize("function_name", ALERTING_FUNCTIONS)
def test_alerting_function_has_all_topic_arns(function_name):
    """
    Every Lambda with alerting call sites must receive all four topic ARNs.

    A missing ARN means send_alert() drops that severity silently, so a discovery
    failure would notify nobody.
    """
    template = _load_template()
    functions = _lambda_resources(template)
    assert function_name in functions, (
        f"{function_name} not found in the synthesized template"
    )

    env = functions[function_name]["Properties"].get("Environment", {}).get(
        "Variables", {}
    )
    missing = sorted(REQUIRED_TOPIC_VARS - set(env))
    assert not missing, (
        f"{function_name} is missing topic ARN environment variables: {missing}. "
        "shared/alerting.py would drop alerts routed to those topics."
    )


def test_alerting_functions_can_publish_to_sns():
    """
    The execution role must hold sns:Publish covering the alerting topics.

    Setting the environment variables without the matching grant turns a silent
    drop into an AccessDenied at publish time -- still an undelivered alert.
    """
    template = _load_template()

    publish_resources = []
    for resource in template.get("Resources", {}).values():
        if resource.get("Type") != "AWS::IAM::Policy":
            continue
        for statement in resource["Properties"]["PolicyDocument"]["Statement"]:
            action = statement.get("Action")
            actions = action if isinstance(action, list) else [action]
            if not any("sns:Publish" in str(a) for a in actions):
                continue
            targets = statement.get("Resource")
            publish_resources.extend(
                targets if isinstance(targets, list) else [targets]
            )

    assert publish_resources, "no IAM policy statement grants sns:Publish"
    # Four alerting topics plus the change-notification topic.
    assert len(publish_resources) >= len(REQUIRED_TOPIC_VARS), (
        f"sns:Publish covers only {len(publish_resources)} topic(s); "
        f"expected at least {len(REQUIRED_TOPIC_VARS)}"
    )


def test_alerting_module_env_vars_match_the_stack():
    """
    Guard against drift between alerting.py and the stack.

    If alerting.py starts reading a new *_TOPIC_ARN variable, this test fails
    until the stack supplies it, rather than the alert silently disappearing.
    """
    alerting = (
        REPO_ROOT / "src" / "lambdas" / "shared" / "alerting.py"
    ).read_text()

    referenced = {
        line.split("'")[1]
        for line in alerting.splitlines()
        if "os.environ.get('" in line and "_TOPIC_ARN" in line
    }
    unwired = sorted(referenced - REQUIRED_TOPIC_VARS)
    assert not unwired, (
        f"alerting.py reads topic variables the stack does not set: {unwired}"
    )
