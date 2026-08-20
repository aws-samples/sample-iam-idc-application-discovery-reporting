"""
Tests for retiring resources whose deletion has already been reported.

Deletion is derived by set difference: a row in DynamoDB that the current
enumeration did not return. Nothing acted on that verdict, so the row stayed and
every later run re-derived the same difference and wrote another change-log record.
Measured in a live account before the fix: 8 genuinely deleted resources produced
89 change-log records, one of them repeated 27 times, and the applications table
held 19 rows for 17 live applications -- drift the CSV exports inherited.

These tests run against moto rather than mocks, because the defect lives in what
DynamoDB actually returns across two successive runs. A Mock table would return
whatever the test told it to and would pass with the retirement code deleted.
"""

import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

REPO = Path(__file__).resolve().parents[1]
SHARED = REPO / 'src' / 'lambdas' / 'shared'


def _load_incremental():
    """
    Load shared.incremental as a real package submodule.

    It uses a relative import (`from .utils import scan_all`), so it cannot be
    loaded standalone by path -- the parent package has to exist first.
    """
    if str(REPO / 'src' / 'lambdas') not in sys.path:
        sys.path.insert(0, str(REPO / 'src' / 'lambdas'))
    for stale in ('shared', 'shared.utils', 'shared.incremental'):
        mod = sys.modules.get(stale)
        # Other test modules install Mocks under these names; a Mock here would
        # make every assertion below pass regardless of the code under test.
        if mod is not None and not hasattr(mod, '__file__'):
            sys.modules.pop(stale)
    from shared import incremental
    return incremental


APP_ARN_LIVE = 'arn:aws:sso::111122223333:application/ssoins-abc/apl-live'
APP_ARN_GONE = 'arn:aws:sso::111122223333:application/ssoins-abc/apl-gone'
INSTANCE_ARN = 'arn:aws:sso:::instance/ssoins-abc'


@pytest.fixture
def tables():
    """Create the three discovery tables with the real key schemas."""
    with mock_aws():
        ddb = boto3.resource('dynamodb', region_name='us-east-1')
        ddb.create_table(
            TableName='instances',
            KeySchema=[{'AttributeName': 'instance_arn', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'instance_arn', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
        )
        # Composite key -- retirement has to supply the range key too.
        ddb.create_table(
            TableName='applications',
            KeySchema=[{'AttributeName': 'application_arn', 'KeyType': 'HASH'},
                       {'AttributeName': 'instance_arn', 'KeyType': 'RANGE'}],
            AttributeDefinitions=[{'AttributeName': 'application_arn', 'AttributeType': 'S'},
                                  {'AttributeName': 'instance_arn', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
        )
        ddb.create_table(
            TableName='assignments',
            KeySchema=[{'AttributeName': 'assignment_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'assignment_id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
        )
        ddb.create_table(
            TableName='change-log',
            KeySchema=[{'AttributeName': 'change_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'change_id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
        )
        ddb.create_table(
            TableName='discovery-state',
            KeySchema=[{'AttributeName': 'state_key', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'state_key', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST',
        )
        os.environ.update({
            'INSTANCES_TABLE': 'instances',
            'APPLICATIONS_TABLE': 'applications',
            'ASSIGNMENTS_TABLE': 'assignments',
            'CHANGE_LOG_TABLE': 'change-log',
            'DISCOVERY_STATE_TABLE': 'discovery-state',
        })
        yield ddb


def _manager(tables):
    incremental = _load_incremental()
    mgr = incremental.IncrementalDiscoveryManager(region_name='us-east-1')
    # Bind directly to the moto tables so the test does not depend on which env
    # var names the constructor happens to read.
    mgr.instances_table = tables.Table('instances')
    mgr.applications_table = tables.Table('applications')
    mgr.assignments_table = tables.Table('assignments')
    mgr.change_log_table_name = 'change-log'
    mgr.dynamodb = tables
    return mgr


def _seed_two_apps(tables):
    apps = tables.Table('applications')
    for arn in (APP_ARN_LIVE, APP_ARN_GONE):
        apps.put_item(Item={'application_arn': arn, 'instance_arn': INSTANCE_ARN,
                            'status': 'ENABLED', 'name': arn.split('/')[-1]})


def _current_apps():
    """What this run's enumeration returns: the live app only."""
    return [{'application_arn': APP_ARN_LIVE, 'instance_arn': INSTANCE_ARN,
             'status': 'ENABLED', 'name': 'apl-live'}]


class TestDeletionIsReportedExactlyOnce:

    def test_first_run_reports_the_deletion(self, tables):
        mgr = _manager(tables)
        _seed_two_apps(tables)

        changes = mgr.detect_application_changes(_current_apps(), 'run-1')

        deleted = [c for c in changes if c.change_type == 'deleted']
        assert len(deleted) == 1
        assert deleted[0].resource_id == APP_ARN_GONE

    def test_second_run_does_not_report_it_again(self, tables):
        """The regression: the same deletion was re-reported on every run."""
        mgr = _manager(tables)
        _seed_two_apps(tables)

        first = mgr.detect_application_changes(_current_apps(), 'run-1')
        mgr.save_changes(first)
        assert mgr.retire_deleted_resources(first) == 1

        second = mgr.detect_application_changes(_current_apps(), 'run-2')

        assert [c for c in second if c.change_type == 'deleted'] == []

    def test_deletion_survives_in_the_change_log(self, tables):
        """Retiring must not erase the audit record of the deletion."""
        mgr = _manager(tables)
        _seed_two_apps(tables)

        changes = mgr.detect_application_changes(_current_apps(), 'run-1')
        mgr.save_changes(changes)
        mgr.retire_deleted_resources(changes)

        logged = tables.Table('change-log').scan()['Items']
        assert [i['resource_id'] for i in logged if i['change_type'] == 'deleted'] == [APP_ARN_GONE]

    def test_retired_row_is_kept_not_deleted(self, tables):
        """The row stays for audit; only a marker is added."""
        mgr = _manager(tables)
        _seed_two_apps(tables)

        changes = mgr.detect_application_changes(_current_apps(), 'run-1')
        mgr.retire_deleted_resources(changes)

        row = tables.Table('applications').get_item(
            Key={'application_arn': APP_ARN_GONE, 'instance_arn': INSTANCE_ARN})['Item']
        assert row['retired_at']
        assert row['status'] == 'ENABLED', "existing attributes must be preserved"

    def test_live_row_is_untouched(self, tables):
        mgr = _manager(tables)
        _seed_two_apps(tables)

        changes = mgr.detect_application_changes(_current_apps(), 'run-1')
        mgr.retire_deleted_resources(changes)

        row = tables.Table('applications').get_item(
            Key={'application_arn': APP_ARN_LIVE, 'instance_arn': INSTANCE_ARN})['Item']
        assert 'retired_at' not in row

    def test_reappearing_resource_is_reported_as_created(self, tables):
        """
        Retirement must not permanently blacklist a resource.

        If an application is deleted and later re-created with the same ARN, the
        second creation is a real event a reviewer needs to see.
        """
        mgr = _manager(tables)
        _seed_two_apps(tables)

        first = mgr.detect_application_changes(_current_apps(), 'run-1')
        mgr.retire_deleted_resources(first)

        both = _current_apps() + [{'application_arn': APP_ARN_GONE, 'instance_arn': INSTANCE_ARN,
                                   'status': 'ENABLED', 'name': 'apl-gone'}]
        changes = mgr.detect_application_changes(both, 'run-2')

        created = [c for c in changes if c.change_type == 'created']
        assert [c.resource_id for c in created] == [APP_ARN_GONE]


class TestRetirementScope:

    def test_only_deletions_are_retired(self, tables):
        mgr = _manager(tables)
        _seed_two_apps(tables)
        incremental = _load_incremental()

        created = incremental.ChangeRecord(
            resource_type='application', resource_id=APP_ARN_LIVE, change_type='created',
            new_data={'application_arn': APP_ARN_LIVE, 'instance_arn': INSTANCE_ARN},
            discovery_run_id='run-1')

        assert mgr.retire_deleted_resources([created]) == 0
        row = tables.Table('applications').get_item(
            Key={'application_arn': APP_ARN_LIVE, 'instance_arn': INSTANCE_ARN})['Item']
        assert 'retired_at' not in row

    def test_assignment_deletion_uses_its_single_key(self, tables):
        mgr = _manager(tables)
        assignments = tables.Table('assignments')
        assignments.put_item(Item={'assignment_id': 'apl-gone#user-1', 'assignment_status': 'ACTIVE'})

        changes = mgr.detect_assignment_changes([], 'run-1')
        # An empty enumeration is the caller's guard, not this method's; drive
        # retirement from the record the detector produced.
        assert mgr.retire_deleted_resources(changes) == 1
        assert assignments.get_item(Key={'assignment_id': 'apl-gone#user-1'})['Item']['retired_at']

    def test_instance_deletion_uses_its_single_key(self, tables):
        mgr = _manager(tables)
        instances = tables.Table('instances')
        instances.put_item(Item={'instance_arn': INSTANCE_ARN, 'status': 'ACTIVE'})

        changes = mgr.detect_instance_changes([], 'run-1')
        assert mgr.retire_deleted_resources(changes) == 1
        assert instances.get_item(Key={'instance_arn': INSTANCE_ARN})['Item']['retired_at']

    def test_record_without_old_data_is_skipped_not_crashed(self, tables):
        """A malformed record must not take down the discovery run."""
        mgr = _manager(tables)
        incremental = _load_incremental()

        orphan = incremental.ChangeRecord(
            resource_type='application', resource_id=APP_ARN_GONE,
            change_type='deleted', old_data=None, discovery_run_id='run-1')

        assert mgr.retire_deleted_resources([orphan]) == 0
