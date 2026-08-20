"""
Pin the stack's context flags to the behaviour they are documented to have.

A context flag that silently stops being read is worse than no flag: the stack
still deploys, cdk-nag still passes, and the operator believes they turned
something on. These tests synthesize the stack twice -- once with the flag absent
and once with it set -- and assert the resulting template differs in the one
property the flag names.
"""

import os
import sys

import aws_cdk as cdk
import pytest
from aws_cdk import assertions

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.stacks.iam_identity_center_discovery_stack import (  # noqa: E402
    IamIdentityCenterDiscoveryStack,
)

# The stack refuses to synthesize with an open IP range unless this is acknowledged.
BASE_CONTEXT = {'acknowledgeOpenIpRange': True}


def _template(stack_id, **context):
    app = cdk.App(context={**BASE_CONTEXT, **context})
    stack = IamIdentityCenterDiscoveryStack(
        app, stack_id,
        env=cdk.Environment(account='123456789012', region='us-east-1'),
    )
    return assertions.Template.from_stack(stack)


def _rest_api_property(template, name):
    apis = template.find_resources('AWS::ApiGateway::RestApi')
    assert len(apis) == 1, f"expected one RestApi, found {len(apis)}"
    return next(iter(apis.values()))['Properties'].get(name)


class TestDisableExecuteApiEndpoint:
    """
    The export API's default execute-api endpoint.

    It has to stay reachable out of the box: this stack creates no custom domain,
    so disabling the default endpoint by default would deploy an API that nothing
    can call, including the requests the README documents. Access is gated by IAM
    authentication and the IP-range resource policy either way, so the endpoint is
    reachable rather than open -- and the flag exists so that adding a custom
    domain later does not mean editing the stack.
    """

    def test_endpoint_is_reachable_by_default(self):
        template = _template('DefaultFlags')
        assert _rest_api_property(template, 'DisableExecuteApiEndpoint') is False

    def test_flag_disables_the_endpoint(self):
        template = _template('EndpointDisabled', disableExecuteApiEndpoint='true')
        assert _rest_api_property(template, 'DisableExecuteApiEndpoint') is True

    @pytest.mark.parametrize('value', ['false', 'False', '', 'no', 'TRUE'])
    def test_flag_parsing_is_explicit_about_true(self, value):
        """
        Only "true", case-insensitively, disables the endpoint.

        The flag arrives as a string from -c, so `if context_value:` would treat
        "false" as enabling it -- a non-empty string is truthy. Anything that is
        not "true" must leave the endpoint reachable, since the failure mode of
        guessing wrong is an unreachable API.
        """
        template = _template(f'Parse{value or "Empty"}', disableExecuteApiEndpoint=value)
        expected = value.lower() == 'true'
        assert _rest_api_property(template, 'DisableExecuteApiEndpoint') is expected

class TestParametersWithNoDefault:
    """
    Parameters whose default would be a silent security decision.

    A CloudFormation parameter with no Default makes stack *creation* fail until a
    value is supplied — verified against the live API, which answers
    `Parameters: [AllowedIpRange] must have values`. A Default turns that into a
    deploy that quietly succeeds with whatever the sample happened to ship, which is
    how both of these came to be wrong: `AllowedIpRange` shipped `0.0.0.0/0` behind
    a synth-time notice, and `CrossAccountExternalId` shipped a value published in
    this repository.

    Note that a stack *update* reuses the previous value, so this only binds on the
    first deploy — which is the one that matters, since it is the deployer who has
    not read the README.
    """

    @pytest.mark.parametrize('parameter', ['AllowedIpRange', 'CrossAccountExternalId'])
    def test_parameter_has_no_default(self, parameter):
        template = _template(f'NoDefault{parameter}').to_json()
        assert parameter in template['Parameters'], f"{parameter} is not a stack parameter"
        assert 'Default' not in template['Parameters'][parameter], (
            f"{parameter} must have no Default: a default here is a security decision "
            f"made on the deployer's behalf, silently"
        )

    def test_open_ip_range_is_still_accepted(self):
        """
        0.0.0.0/0 must remain a legal value.

        Requiring the parameter makes the open range a decision instead of an
        omission; it does not forbid it. Demos need it, and a constraint that blocks
        it would push people to edit the stack instead.
        """
        template = _template('OpenRangeAllowed').to_json()
        pattern = template['Parameters']['AllowedIpRange']['AllowedPattern']

        import re
        assert re.match(pattern, '0.0.0.0/0')
        assert re.match(pattern, '10.0.0.0/8')
        assert not re.match(pattern, 'not-a-cidr')

    def test_external_id_rejects_the_published_value(self):
        """
        The CfnRule blocking the value this repository shipped must survive.

        Asserted against the rule's `Assert` expression, not its `AssertDescription`.
        The description has to quote the forbidden value in order to explain itself,
        so a substring search over the whole rule passes on the prose alone — it
        stayed green when the assertion was repointed at a different value, which is
        the only mutation that matters here.
        """
        template = _template('ExternalIdRule').to_json()
        rules = template.get('Rules', {})

        rule = rules.get('CrossAccountExternalIdMustNotBePublished')
        assert rule, "the guard rule is gone"

        equals = rule['Assertions'][0]['Assert']['Fn::Not'][0]['Fn::Equals']
        assert {'Ref': 'CrossAccountExternalId'} in equals, (
            "the rule no longer tests the CrossAccountExternalId parameter"
        )
        assert 'iam-identity-center-discovery' in equals, (
            "the rule no longer rejects the value published in this repository"
        )


class TestApiGatewayGuards:

    def test_iam_auth_and_ip_policy_apply_regardless(self):
        """
        The endpoint being reachable is not the same as it being open.

        Asserted alongside the flag because the flag's default is only defensible
        while these two controls are in place.
        """
        for stack_id, context in [('GuardsDefault', {}),
                                  ('GuardsDisabled', {'disableExecuteApiEndpoint': 'true'})]:
            template = _template(stack_id, **context)
            policy = _rest_api_property(template, 'Policy')
            assert policy, "the RestApi must carry a resource policy"

            methods = template.find_resources('AWS::ApiGateway::Method')
            authorizations = {
                props['Properties'].get('AuthorizationType')
                for props in methods.values()
                if props['Properties'].get('HttpMethod') != 'OPTIONS'
            }
            assert authorizations == {'AWS_IAM'}, (
                f"every non-OPTIONS method must require IAM auth, got {authorizations}"
            )
