"""
Regression tests for the distinction between "we could not determine this" and
"we determined this is absent".

Three separate places used to collapse those two states into one, and in each
case the collapsed value was the one that drives an operator toward revoking
access:

  * access-tracker treated an aborted CloudTrail query as proof that an
    assignment had never been used, counted it in assignments_never_accessed,
    marked it stale, and named a source it had not successfully read.
  * assignment-discovery treated any Identity Store lookup failure -- including
    AccessDenied and throttling -- as "principal deleted", so a transient error
    silently relabelled live users and groups.
  * incremental reported the full inventory under a field named
    estimated_scope with optimization_strategy 'timestamp_based', which reads
    as though a subset had been selected.

Each test asserts on the distinction, not merely on the happy path.
"""

import importlib.util
import os
import sys
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

_LAMBDAS = os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas')
sys.path.insert(0, _LAMBDAS)


def _load(lambda_dir, alias):
    """Load a Lambda's index.py under a unique module name.

    Every Lambda in this solution names its entry point index.py, so a plain
    'import index' binds sys.modules['index'] to whichever one is imported
    first and every later import silently returns that same module. Tests then
    assert against the wrong Lambda. Loading by explicit path under a distinct
    alias keeps them separate.
    """
    if alias in sys.modules:
        return sys.modules[alias]
    path = os.path.join(_LAMBDAS, lambda_dir, 'index.py')
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    sys.path.insert(0, os.path.join(_LAMBDAS, lambda_dir))
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# access-tracker: an aborted CloudTrail read is not evidence of non-use
# ---------------------------------------------------------------------------

class TestCloudTrailCompleteness:
    """_query_cloudtrail_events must report whether it read the whole window."""

    def _tracker(self):
        return _load('access-tracker', 'access_tracker_index')

    def test_failed_query_reports_incomplete(self):
        """A query that raises must return complete=False, not an empty success."""
        index = self._tracker()
        client = Mock()
        client.lookup_events = Mock(side_effect=Exception("Throttling"))

        total, complete = index._query_cloudtrail_events(
            client, datetime.now(timezone.utc), datetime.now(timezone.utc), {}, "us-east-1"
        )

        assert complete is False, (
            "an aborted CloudTrail query reported itself as a complete read; "
            "downstream code will treat zero events as 'never accessed'"
        )
        assert total == 0

    def test_clean_query_reports_complete(self):
        """A query that finishes must report complete=True so real absences count."""
        index = self._tracker()
        client = Mock()
        client.lookup_events = Mock(return_value={'Events': []})

        total, complete = index._query_cloudtrail_events(
            client, datetime.now(timezone.utc), datetime.now(timezone.utc), {}, "us-east-1"
        )

        assert complete is True
        assert total == 0

    def test_partial_page_failure_reports_incomplete(self):
        """Failing on a later page must not be reported as a complete read."""
        index = self._tracker()
        client = Mock()
        client.lookup_events = Mock(side_effect=[
            {'Events': [{'EventName': 'Authenticate'}], 'NextToken': 'more'},
            Exception("ThrottlingException"),
        ])

        total, complete = index._query_cloudtrail_events(
            client, datetime.now(timezone.utc), datetime.now(timezone.utc), {}, "us-east-1"
        )

        assert complete is False, (
            "a query that read page 1 and then failed claimed a complete read"
        )


# ---------------------------------------------------------------------------
# assignment-discovery: a lookup failure is not a deletion
# ---------------------------------------------------------------------------

class TestPrincipalLookupFailure:
    """Only ResourceNotFound means deleted. Everything else must raise."""

    def _discovery(self):
        return _load('assignment-discovery', 'assignment_discovery_index')

    def test_access_denied_raises_rather_than_reporting_deleted(self):
        index = self._discovery()
        client = Mock()

        with patch.object(index, 'safe_api_call',
                          return_value=(False, None, 'AccessDeniedException: not authorized')):
            with pytest.raises(index.PrincipalLookupFailed):
                index.get_group_details(client, 'd-example', 'group-1')

    def test_throttling_raises_rather_than_reporting_deleted(self):
        index = self._discovery()
        client = Mock()

        with patch.object(index, 'safe_api_call',
                          return_value=(False, None, 'ThrottlingException: rate exceeded')):
            with pytest.raises(index.PrincipalLookupFailed):
                index.get_user_details(client, 'd-example', 'user-1')

    def test_resource_not_found_returns_none(self):
        """A genuinely deleted principal is the one case that may return None."""
        index = self._discovery()
        client = Mock()

        with patch.object(index, 'safe_api_call',
                          return_value=(False, None, 'ResourceNotFoundException: no such group')):
            assert index.get_group_details(client, 'd-example', 'group-1') is None

    def test_successful_lookup_returns_details(self):
        index = self._discovery()
        client = Mock()

        with patch.object(index, 'safe_api_call',
                          return_value=(True, {'DisplayName': 'Finance'}, None)):
            result = index.get_group_details(client, 'd-example', 'group-1')

        assert result is not None
        assert result['principal_name'] == 'Finance'


# ---------------------------------------------------------------------------
# incremental: the plan must not advertise an optimization it does not perform
# ---------------------------------------------------------------------------

class TestIncrementalPlanHonesty:
    """The plan reports the full inventory, so it must say so."""

    def _plan(self):
        from shared.incremental import IncrementalDiscoveryManager

        manager = IncrementalDiscoveryManager.__new__(IncrementalDiscoveryManager)
        state = Mock()
        state.last_full_discovery = None
        state.last_incremental_discovery = None
        state.change_detection_enabled = True
        state.total_instances = 3
        state.total_applications = 40
        state.total_assignments = 900
        manager.get_discovery_state = Mock(return_value=state)
        return manager.create_incremental_discovery_plan('run-1')

    def test_plan_does_not_claim_an_optimization_strategy(self):
        plan = self._plan()
        assert 'optimization_strategy' not in plan, (
            "the plan advertises an optimization strategy while every discovery "
            "Lambda still re-enumerates the full inventory"
        )
        assert plan['narrowing_strategy'] == 'none'

    def test_plan_declares_its_scope_is_the_full_inventory(self):
        plan = self._plan()
        assert plan['scope']['scope_is_full_inventory'] is True
        # The counts are the full totals, which is exactly why they must not be
        # presented as an estimate of a narrowed subset.
        assert plan['scope']['applications_to_check'] == 40
        assert plan['scope']['assignments_to_check'] == 900

    def test_plan_no_longer_uses_the_estimated_scope_label(self):
        assert 'estimated_scope' not in self._plan()
