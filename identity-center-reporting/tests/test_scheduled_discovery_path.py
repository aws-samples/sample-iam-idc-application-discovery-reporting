"""
Pin the input the daily EventBridge rule sends to the state machine.

Nothing guarded this before, which is how it regressed silently. The rule used to
send force_full_discovery=false, which routes CheckDiscoveryType to
CheckIncrementalEligibility and puts the run on the incremental branch:

    InitializeIncrementalDiscovery
      -> IncrementalInstanceScanner
      -> ProcessIncrementalResults
      -> EnrichIncrementalWithLastAccessed
      -> IncrementalDiscoveryComplete

That branch never reaches ApplicationDiscovery or AssignmentDiscovery, and
instance-scanner discovers instances only -- it does not reference
discovery_type or incremental_plan at all. So the daily run refreshed instances
and last-accessed data while applications and assignments went stale until
someone triggered a full run by hand. For a solution whose purpose is reporting
on application assignments, the scheduled path silently not refreshing
assignments is the failure that matters.

These tests assert the input and the routing contract together, so changing
either one alone fails here rather than in production a day later.
"""

import json
import os
import re
import subprocess
import sys

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TEMPLATE = os.path.join(_REPO, 'cdk.out', 'IamIdentityCenterDiscoveryStack-dev.template.json')
_STATE_MACHINE = os.path.join(_REPO, 'src', 'step-functions', 'discovery-state-machine.json')


def _template():
    if not os.path.exists(_TEMPLATE):
        pytest.skip("cdk.out template not found -- run 'cdk synth' first")
    with open(_TEMPLATE) as f:
        return json.load(f)


def _daily_rule_input(template):
    """Return the InputTemplate the daily discovery rule sends, or None."""
    for resource in template['Resources'].values():
        if resource['Type'] != 'AWS::Events::Rule':
            continue
        if 'daily-discovery' not in json.dumps(resource):
            continue
        for target in resource['Properties'].get('Targets', []):
            body = target.get('InputTransformer', {}).get('InputTemplate', '')
            if 'force_full_discovery' in body:
                return body
    return None


class TestScheduledDiscoveryTakesTheFullPath:

    def test_daily_rule_requests_full_discovery(self):
        body = _daily_rule_input(_template())
        assert body is not None, "daily discovery rule sends no force_full_discovery"

        match = re.search(r'force_full_discovery"\s*:\s*(\w+)', body)
        assert match, f"could not read force_full_discovery from: {body[:200]}"
        assert match.group(1) == 'true', (
            "the daily rule sends force_full_discovery=false, which routes the "
            "scheduled run onto the incremental branch. That branch does not run "
            "ApplicationDiscovery or AssignmentDiscovery, so applications and "
            "assignments stop being refreshed by the schedule."
        )

    def test_full_path_reaches_application_and_assignment_discovery(self):
        """The routing half of the contract: full really does mean full."""
        with open(_STATE_MACHINE) as f:
            states = json.load(f)['States']

        choice = states['CheckDiscoveryType']
        full_target = next(
            c['Next'] for c in choice['Choices']
            if c['Variable'] == '$.force_full_discovery'
        )
        assert full_target == 'InitializeDiscovery', (
            f"force_full_discovery no longer routes to InitializeDiscovery "
            f"(now {full_target}); the test above no longer proves what it claims"
        )

        # Walk the whole graph from InitializeDiscovery and confirm the two
        # stages that matter are reachable.
        reachable, frontier = set(), ['InitializeDiscovery']
        while frontier:
            name = frontier.pop()
            if name in reachable or name not in states:
                continue
            reachable.add(name)
            state = states[name]
            for key in ('Next', 'Default'):
                if state.get(key):
                    frontier.append(state[key])
            for c in state.get('Choices', []):
                if c.get('Next'):
                    frontier.append(c['Next'])
            it = state.get('Iterator') or state.get('ItemProcessor')
            if it:
                frontier.extend(it.get('States', {}).keys())

        for required in ('ApplicationDiscovery', 'AssignmentDiscovery'):
            assert any(required in r for r in reachable), (
                f"{required} is not reachable from InitializeDiscovery; "
                f"reached: {sorted(reachable)}"
            )

    def test_incremental_branch_still_skips_those_stages(self):
        """
        Documents why the input matters, and fails if someone fixes the
        incremental branch without revisiting the scheduled default.
        """
        with open(_STATE_MACHINE) as f:
            states = json.load(f)['States']

        reachable, frontier = set(), ['InitializeIncrementalDiscovery']
        while frontier:
            name = frontier.pop()
            if name in reachable or name not in states:
                continue
            reachable.add(name)
            state = states[name]
            for key in ('Next', 'Default'):
                if state.get(key):
                    frontier.append(state[key])
            for c in state.get('Choices', []):
                if c.get('Next'):
                    frontier.append(c['Next'])

        skipped = [s for s in ('ApplicationDiscovery', 'AssignmentDiscovery')
                   if not any(s in r for r in reachable)]
        assert skipped == ['ApplicationDiscovery', 'AssignmentDiscovery'], (
            "The incremental branch now reaches "
            f"{[s for s in ('ApplicationDiscovery', 'AssignmentDiscovery') if s not in skipped]}. "
            "That is an improvement -- update this test and reconsider whether the "
            "daily rule should still force a full run."
        )


class TestInstanceScopeParameter:
    """
    Guard the IdentityCenterInstanceId parameter and the ListInstances split.

    Scoping the sso permissions to one instance ID broke discovery in a way the
    state machine reported as SUCCEEDED: sso:ListInstances has no resource type
    and IAM evaluates it against the literal resource arn:aws:sso:::instance/*,
    which a specific instance ARN can never match. That produced 70 AccessDenied
    events while the run still looked clean, because the discovery code treats a
    region it could not read as a region with nothing in it.
    """

    def test_list_instances_has_its_own_wildcard_statement(self):
        template = _template()
        found = []

        def walk(node):
            if isinstance(node, dict):
                if str(node.get('Sid', '')).startswith('SSO'):
                    actions = node.get('Action')
                    actions = actions if isinstance(actions, list) else [actions]
                    found.append((node['Sid'], actions, json.dumps(node.get('Resource'))))
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(template)
        assert found, 'no SSO statements in the synthesized template'

        for sid, actions, resource in found:
            if 'sso:ListInstances' not in actions:
                continue
            assert len(actions) == 1, (
                f'{sid} grants sso:ListInstances alongside {actions}. It must be '
                f'alone, on arn:aws:sso:::instance/*, because it has no resource '
                f'type -- bundling it with scopeable actions means a real instance '
                f'ID silently denies every ListInstances call.'
            )
            assert 'instance/*' in resource, (
                f'{sid} grants sso:ListInstances on {resource}; IAM evaluates that '
                f'action against arn:aws:sso:::instance/* and nothing narrower can match'
            )

    def test_instance_scope_defaults_to_the_wildcard_arn(self):
        """
        The default must stay the wildcard ARN.

        This organization has three Identity Center instances across three
        accounts, so a narrower default would silently reduce organization-wide
        discovery to a single-instance report.

        It must also be a whole ARN, not a bare '*'. The instance ID is derived
        with Fn::Select(1, Fn::Split('instance/', ...)), and splitting a bare '*'
        yields a one-element list -- Fn::Select(1, ...) on that is a deploy-time
        CloudFormation error, not a fallback.
        """
        template = _template()
        parameter = template.get('Parameters', {}).get('IdentityCenterInstanceArn')
        assert parameter is not None, (
            'IdentityCenterInstanceArn parameter is missing; the reporting stack '
            'uses the same parameter name as the reactive-monitoring stack'
        )
        assert parameter.get('Default') == 'arn:aws:sso:::instance/*', (
            f"default is {parameter.get('Default')!r}; it must be the wildcard ARN "
            f"so that organization-wide discovery keeps working and the Fn::Split "
            f"derivation still yields two elements"
        )

    def test_scope_parameter_is_at_parity_with_reactive_monitoring(self):
        """
        Both stacks take the instance ARN under the same name and derive the ID
        the same way, so an operator supplies one value in one form to either.
        """
        monitor = os.path.join(
            os.path.dirname(_REPO), 'identity-center-remediation',
            'lib', 'identity-center-app-monitor-stack.ts'
        )
        if not os.path.exists(monitor):
            pytest.skip('reactive-monitoring stack not present')
        source = open(monitor).read()
        assert "'IdentityCenterInstanceArn'" in source, (
            'the reactive-monitoring stack no longer declares '
            'IdentityCenterInstanceArn; the two stacks have drifted apart'
        )
        assert "Fn.split('instance/'" in source, (
            'the reactive-monitoring stack no longer derives the instance ID with '
            "Fn.split('instance/', ...); this stack does, so they have drifted"
        )
