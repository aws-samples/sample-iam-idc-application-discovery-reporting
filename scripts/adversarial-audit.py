#!/usr/bin/env python3
"""
Adversarial invariant audit for this repository.

This does not check that an intended change was made. It checks that things
which were true before an edit are still true after it -- the class of breakage
a "does it compile / did the edit apply" check cannot see.

Every check here exists because that exact bug was actually introduced during
development, not because it seemed like a good idea:

  decorators      A helper inserted between a decorator and its function moved
                  @trace_lambda_handler onto the wrong target. The file compiled.
  structure       A regex deletion of the last test in a class consumed the
                  following `class Foo:` line and merged its methods into the
                  test class. The stray __init__ made pytest silently refuse to
                  collect the whole class -- 11 tests stopped running and the
                  suite still reported success.
  collection      Same bug, detected from the other side: assert the number of
                  collected tests never drops without intent.
  anchors         A README cross-reference was added to a heading that did not
                  exist.
  pii             Redaction was applied to nine log sites and missed two, and
                  one "redaction" still emitted the user's email because the
                  trailing ARN segment IS the email for an Identity Center role.
  examples        Docs described substring matching for months after the code
                  moved to whole-word matching.
  deadcode        A module-level helper with no callers looked like live
                  machinery.

Usage:
    python3 scripts/adversarial-audit.py                 # audit current tree
    python3 scripts/adversarial-audit.py --baseline FILE # write a baseline
    python3 scripts/adversarial-audit.py --against FILE  # compare to baseline

Exit code 0 = no findings. 1 = findings. Baseline mode always exits 0.
"""

import argparse
import ast
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The scripts directories are in scope deliberately.
#
# They were not, and it cost two findings an external review had to catch: the
# post-deployment verification script printed live principal IDs and raw response
# bodies, and the cross-account deploy script hardcoded the ExternalId. Operator
# scripts are the code most likely to be run by hand against a production account
# and the code most likely to be copied, so excluding them inverted the priority.
PY_ROOTS = [
    'identity-center-reporting/src',
    'identity-center-reporting/lib',
    'identity-center-reporting/scripts',
    'identity-center-remediation/lambda',
]
MD_FILES = ['README.md', 'identity-center-reporting/README.md',
            'identity-center-remediation/README.md']

findings = []


def finding(check, path, detail):
    findings.append({'check': check, 'path': path, 'detail': detail})


def py_files():
    for root in PY_ROOTS:
        base = os.path.join(REPO, root)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames
                           if d not in {'__pycache__', '.venv', 'node_modules', 'cdk.out'}]
            for fn in filenames:
                if fn.endswith('.py'):
                    yield os.path.join(dirpath, fn)


def rel(p):
    return os.path.relpath(p, REPO)


# ---------------------------------------------------------------------------
# structure: what each file defines, and what decorates what
# ---------------------------------------------------------------------------

def structure():
    """Map file -> {classes, functions, decorator->target pairs}."""
    out = {}
    for path in py_files():
        try:
            tree = ast.parse(open(path).read())
        except SyntaxError as e:
            finding('syntax', rel(path), f'does not parse: {e}')
            continue
        classes, funcs, decorated = [], [], []

        def walk(node, prefix=''):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    classes.append(prefix + child.name)
                    walk(child, prefix + child.name + '.')
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    funcs.append(prefix + child.name)
                    for d in child.decorator_list:
                        name = (getattr(d, 'id', None)
                                or getattr(getattr(d, 'func', None), 'id', None)
                                or getattr(d, 'attr', None))
                        if name:
                            decorated.append(f'{name}->{prefix}{child.name}')
                    walk(child, prefix + child.name + '.')

        walk(tree)
        out[rel(path)] = {'classes': sorted(classes),
                          'functions': sorted(funcs),
                          'decorated': sorted(decorated)}
    return out


def check_test_class_collectable():
    """A test class with __init__ is silently skipped by pytest."""
    tests = os.path.join(REPO, 'identity-center-reporting', 'tests')
    for dirpath, _, filenames in os.walk(tests):
        for fn in filenames:
            if not (fn.startswith('test_') and fn.endswith('.py')):
                continue
            path = os.path.join(dirpath, fn)
            try:
                tree = ast.parse(open(path).read())
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name.startswith('Test'):
                    if any(isinstance(m, ast.FunctionDef) and m.name == '__init__'
                           for m in node.body):
                        finding('collection', rel(path),
                                f'test class {node.name} defines __init__; pytest '
                                f'will refuse to collect it and every test inside '
                                f'it stops running silently')


def check_orphan_methods():
    """Private helpers with no self.<name>( caller anywhere in their file."""
    for path in py_files():
        src = open(path).read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for m in node.body:
                if isinstance(m, ast.FunctionDef) and m.name.startswith('_') \
                        and not m.name.startswith('__'):
                    if not re.search(rf'self\.{re.escape(m.name)}\s*\(', src):
                        finding('deadcode', f'{rel(path)}:{m.lineno}',
                                f'{node.name}.{m.name} has no caller in this file')


def check_anchors():
    def slug(h):
        s = h.strip().lower()
        s = re.sub(r'[^\w\s-]', '', s)
        return s.replace(' ', '-')
    for name in MD_FILES:
        path = os.path.join(REPO, name)
        if not os.path.exists(path):
            continue
        src = open(path).read()
        anchors = {slug(m.group(2)) for m in re.finditer(r'^(#{1,6})\s+(.+)$', src, re.M)}
        for m in re.finditer(r'\[([^\]]+)\]\(#([^)]+)\)', src):
            if m.group(2).lower() not in anchors:
                line = src[:m.start()].count('\n') + 1
                finding('anchors', f'{name}:{line}',
                        f'[{m.group(1)}](#{m.group(2)}) resolves to no heading')


PII_TOKENS = ('principal_id', 'principal_name', 'principal_email', 'display_name',
              'user_arn', 'UserName', 'principalId', 'DisplayName')

# Subscript access to a field holding a name or an address.
#
# The token list above was not enough. It missed `details['name']`, which holds a
# resolved Identity Store UserName -- and the Content Security Review rated two
# such log lines HIGH once a module header was added stating those values must be
# redacted. Matching only variables *named* like PII misses PII reached through a
# dictionary key, which is how API responses are actually handled in this code.
PII_SUBSCRIPT = re.compile(
    r"""\[\s*['"](?:name|email|emails|username|user_name|display_name"""
    r"""|UserName|DisplayName|Email|Emails)['"]\s*\]"""
)

# The same key on an AWS resource object is that resource's name, not a person's.
#
# `execution['name']` is a Step Functions execution name; `stack['name']` is a
# CloudFormation stack. The subscript rule keys on the dictionary key alone, so it
# read both as resolved identities. Widening the key list was not the fix -- 'name'
# genuinely is the leak on an Identity Store record -- so the owner has to be part
# of the judgement.
NON_IDENTITY_SUBSCRIPT_OWNERS = frozenset({
    'execution', 'executions', 'stack', 'stacks', 'rule', 'rules', 'sm',
    'state_machine', 'table', 'bucket', 'topic', 'alarm', 'function', 'output',
    'app', 'application', 'instance', 'account', 'region', 'log_group',
})
PII_KEYS = frozenset({
    'name', 'email', 'emails', 'username', 'user_name', 'display_name',
    'UserName', 'DisplayName', 'Email', 'Emails',
})
OWNED_SUBSCRIPT = re.compile(
    r"""([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*['"]([A-Za-z_]+)['"]\s*\]"""
)


def _identity_subscripts(seg):
    """
    PII-keyed subscripts in this segment that are NOT reading an AWS resource object.

    Judged per subscript, not per segment. Exempting the whole line as soon as one
    resource-owned subscript appeared meant
    f"{execution['name']} for {user['email']}" passed -- the resource reference
    covered for the identity one sitting beside it.

    A PII-keyed subscript whose owner cannot be parsed (a call result, a chained
    expression) is reported rather than exempted: an unreadable owner is not evidence
    that it is a resource.
    """
    owned = {(m.group(1), m.group(2)) for m in OWNED_SUBSCRIPT.finditer(seg)}
    parsed_keys = {key for _, key in owned}

    offenders = [f"{owner}['{key}']" for owner, key in sorted(owned)
                 if key in PII_KEYS and owner not in NON_IDENTITY_SUBSCRIPT_OWNERS]

    # A PII key present in the segment that no owner-pattern accounted for.
    for m in PII_SUBSCRIPT.finditer(seg):
        key = m.group(0).strip('[] ').strip('\'"')
        if key not in parsed_keys:
            offenders.append(m.group(0))

    return offenders

# Variables holding a resolved identity name.
#
# Three successive Content Security Review rounds found log statements this file
# did not: group_name, user_name, grp_name, existing_name/new_name. Enumerating
# identity variable names does not converge -- each round invents a new one. So
# invert it: treat any *_name variable in a logging call as an identity name
# unless it is on the allowlist of names that describe resources rather than
# people. A new identity variable is then caught by default, and a new resource
# variable produces one false positive that is cheap to allowlist.
NON_IDENTITY_NAMES = frozenset({
    'application_name', 'app_name', 'permission_set_name', 'resource_name',
    'table_name', 'function_name', 'bucket_name', 'rule_name', 'stack_name',
    'topic_name', 'queue_name', 'key_name', 'policy_name', 'field_name',
    'file_name', 'log_group_name', 'instance_name', 'provider_name',
    'domain_name', 'region_name', 'operation_name', 'metric_name',
    'account_name', 'state_machine_name', 'alarm_name', 'export_name',
    'service_name', 'event_name',
    # Bare `name` consistently means a resource name in this codebase --
    # application.name, a cached application name. Identity names here are always
    # principal_name, user_name, group_name or display_name, or are reached
    # through ['name'], which PII_SUBSCRIPT covers, so allowing the bare form
    # does not open a gap.
    'name',
    # Surfaced when the operator scripts came into scope. None of these name a
    # person: an AWS CLI profile, the IAM role the deployer assumes to create the
    # discovery role, and a CloudFormation stack.
    'profile_name', 'assume_role_name', 'role_to_assume', 'stack_name',
})

# Sites where logging an identity name is the point.
#
# The reactive-monitoring log entry IS the compliance alert: one that will not say
# which group was assigned cannot be triaged. That is a decision, recorded at the
# site, not an oversight -- so the audit needs a way to see the decision instead of
# reporting it every run and training people to skip the output.
INTENTIONAL_MARKER = 'audit-allow: identity-name-is-the-alert'
NAME_LIKE = re.compile(r'^([a-z][a-z0-9_]*_name|name)$')

# Identity variables holding an ID rather than a name.
#
# The *_name rule missed user_id and group_id, which hold Identity Store principal
# UUIDs -- six log statements in assignment-discovery emitted them verbatim, and a
# review round caught it. PII_TOKENS covered principal_id but not the per-type
# variants, which is the same enumeration trap as before. Invert it the same way:
# any *_id in a logging call is an identity ID unless it names a resource.
# assignment_id is deliberately NOT here. It was, and that was wrong: the value is
# "<application-id>#<principal-id>", so logging it whole emits the principal UUID
# that principal_id is redacted for. A composite key inherits the sensitivity of
# every part it concatenates, and an allowlist entry judged on the name alone
# missed that -- the name says "assignment", the value carries a person.
NON_IDENTITY_IDS = frozenset({
    'application_id', 'app_id', 'instance_id', 'account_id', 'request_id',
    'discovery_run_id', 'permission_set_id', 'domain_id',
    'identity_store_id', 'store_id', 'key_id', 'run_id', 'event_id',
    'execution_id', 'correlation_id', 'trace_id', 'api_id', 'stack_id',
    'topic_id', 'rule_id', 'log_id', 'directory_id', 'provider_id',
    'current_account_id', 'delegated_admin_account_id', 'management_account_id',
    'delegated_admin_identity_store_id',
    # SNS message IDs, from response['MessageId'].
    'message_id',
    # A bare 'Id' key in an AWS response is a resource ID -- an organization, an
    # account, an application. Identity Store principals are never spelled that
    # way in this codebase: they are PrincipalId, UserId, GroupId, or
    # principal_id, all of which still classify as identity IDs. Allowing the
    # bare form is what keeps org_info.get('Id') from being a finding on every
    # scan; if a principal ever arrives under a plain 'Id', the name is the wrong
    # thing to be trusting and the field needs renaming, not an exception here.
    'id',
    # Also from the scripts: an AWS Organizations ID, and the STS AssumedRoleId of
    # the discovery role, whose session name this script sets itself
    # ("ValidationTest-<account>") rather than inheriting from a federated login.
    'org_id', 'assumed_role_id',
})
ID_LIKE = re.compile(r'^([a-z][a-z0-9_]*_id|id)$')

# Any call that reduces a value before it is logged: redact_principal,
# redact_assignment_id, _caller_role, _caller_digest, and whatever comes next.
REDACTION_CALL = re.compile(r'\b_?(redact[a-z0-9_]*|caller_[a-z0-9_]+|[a-z0-9_]*digest)\s*\(')


def _logged_identifiers(node):
    """
    Names actually interpolated or passed into a logging call.

    Deliberately AST-based. A regex over the source segment also matched the word
    "name" inside message prose -- 'Error retrieving application name for %s'
    produced a finding with no variable involved. Two of four findings on the
    first run of this check were that false positive, and a check that cries wolf
    gets ignored, which is worse than not having it.
    """
    found = set()

    def collect(expr):
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name):
                found.add(sub.id)
            elif isinstance(sub, ast.Attribute):
                found.add(sub.attr)
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                # A dict key reached through .get('PrincipalId'). Normalised so the
                # AWS-API spelling classifies the same as the Python one.
                found.add(_snake(sub.value))

    for arg in node.args[1:]:          # skip the format string itself
        collect(arg)
    for kw in node.keywords:
        if kw.value is not None:
            collect(kw.value)
    for arg in node.args[:1]:          # an f-string in position 0
        if isinstance(arg, ast.JoinedStr):
            for piece in arg.values:
                if isinstance(piece, ast.FormattedValue):
                    collect(piece.value)
    return found


def _snake(text):
    """
    PrincipalId -> principal_id.

    AWS API responses spell these keys in CamelCase, and Python locals spell the
    same thing in snake_case. Classifying only the snake form let
    assignment_data.get('PrincipalId') through while flagging
    assignment_data.get('principal_id') -- the same field, the same leak, one
    spelling. Normalising makes the category independent of which side of the SDK
    boundary the name came from.
    """
    return re.sub(r'(?<!^)(?=[A-Z])', '_', text).lower()


def _interpolated_identifiers(expr):
    """
    Names interpolated into an expression that builds a string.

    Only the interpolated parts count: for an f-string that is the FormattedValue
    nodes, for a concatenation both operands. Collecting every Name in the
    expression would flag the literal message text's own variables and produce the
    false positives _logged_identifiers was already rewritten to avoid.
    """
    found = set()
    for sub in ast.walk(expr):
        if isinstance(sub, ast.FormattedValue):
            for inner in ast.walk(sub.value):
                if isinstance(inner, ast.Name):
                    found.add(inner.id)
                elif isinstance(inner, ast.Attribute):
                    found.add(inner.attr)
                elif isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                    found.add(inner.value)
                    found.add(_snake(inner.value))
    return found


def _classify_pii(path, lineno, seg, identifiers, note=''):
    """
    Report the first way this segment leaks an identity field, if any.

    Shared by the two kinds of site this check looks at -- a logging call, and an
    assignment that builds a string later logged -- so both apply exactly the same
    rules. Duplicating the rules per site is how the second site came to have none.
    """
    where = f'{rel(path)}:{lineno}'

    for tok in PII_TOKENS:
        if re.search(rf'[{{,(\s\'"]{re.escape(tok)}\b', seg):
            finding('pii', where, f'logs {tok} without redaction{note}')
            return True

    offenders = _identity_subscripts(seg)
    if offenders:
        finding('pii', where,
                f"logs {offenders[0]} without redaction -- a resolved "
                f"name or address reached through a dictionary key{note}")
        return True

    # whole-object interpolation of an API response
    if re.search(r'\{(assignment|user|group|response|event|item)\}', seg):
        finding('pii', where,
                f'interpolates a whole API object into a log line{note}')
        return True

    for candidate in sorted(identifiers):
        if NAME_LIKE.match(candidate) and candidate not in NON_IDENTITY_NAMES:
            finding('pii', where,
                    f"logs {candidate} without redaction -- treated as a "
                    f"resolved identity name; add it to NON_IDENTITY_NAMES "
                    f"if it names a resource rather than a person{note}")
            return True
        if ID_LIKE.match(candidate) and candidate not in NON_IDENTITY_IDS:
            finding('pii', where,
                    f"logs {candidate} without redaction -- treated as an "
                    f"identity principal ID; add it to NON_IDENTITY_IDS if "
                    f"it identifies a resource rather than a person{note}")
            return True
    return False


LOG_METHODS = ('info', 'warning', 'error', 'debug', 'exception')


def _emits_output(fn):
    """
    True for a call that writes somewhere a person or a log stream can read it.

    print() counts, not just logger.*. The operator scripts communicate entirely
    through print, so restricting this to logger methods meant the check could not
    see the one place that reads the live assignments table and prints what it
    finds -- which is where an external review found unredacted principal IDs. A
    terminal, a scrollback buffer and a CI job log are all log streams; what makes
    something a logging site is that the value leaves the process, not which
    library carried it.
    """
    if isinstance(fn, ast.Attribute) and fn.attr in LOG_METHODS:
        return True
    return isinstance(fn, ast.Name) and fn.id == 'print'


def check_pii_logging():
    """Log statements interpolating identity fields without redaction."""
    for path in py_files():
        src = open(path).read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        lines = src.split('\n')

        def segment(node):
            return '\n'.join(lines[node.lineno - 1:getattr(node, 'end_lineno', node.lineno)])

        # An explicit, sited decision that the identity belongs in the output.
        if INTENTIONAL_MARKER in src:
            continue

        # Assignments that build a string out of an identity field, keyed by target,
        # scoped to the function they appear in.
        #
        # A logging call that passes only a variable shows this check an ast.Name and
        # nothing else, so PII interpolated one line earlier was invisible:
        #
        #     error_msg = f"... {assignment_data.get('PrincipalId')} ..."
        #     logger.warning(error_msg)          # <- looked clean
        #
        # Treating the assignment as the site is what catches it, and it is also the
        # correct place to demand the fix: those strings have a second consumer,
        # result.add_error(), so redacting at the log call alone would leave the raw
        # ID travelling onward through the error report.
        #
        # Scoping to the function matters. Built file-wide, `error_msg` in one
        # function matched a logger call in another, and the finding pointed at a log
        # line hundreds of lines away in unrelated code -- right about the leak,
        # wrong about where it surfaced, which is the kind of detail that gets a
        # check disbelieved.
        scopes = [n for n in ast.walk(tree)
                  if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module))]
        for scope in scopes:
            # Statements belonging to this scope but not to a nested function, so an
            # inner function's variables do not leak into the outer scope's map.
            nested = {inner for n in ast.iter_child_nodes(scope)
                      for inner in ast.walk(n)
                      if isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and inner is not scope}
            own = []
            for node in ast.walk(scope):
                if node is scope:
                    own.append(node)
                    continue
                if any(node in set(ast.walk(f)) for f in nested):
                    continue
                own.append(node)

            tainted = {}
            for node in own:
                if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                    continue
                target = node.targets[0]
                if not isinstance(target, ast.Name):
                    continue
                if REDACTION_CALL.search(segment(node)):
                    continue
                names = _interpolated_identifiers(node.value)
                if names:
                    tainted[target.id] = (node, names)

            reported = set()
            for node in own:
                if not isinstance(node, ast.Call):
                    continue
                fn = node.func
                if not _emits_output(fn):
                    continue
                seg = segment(node)

                # The tainted-variable case is checked BEFORE the redaction
                # short-circuit below, deliberately. Wrapping the finished message --
                # logger.warning(redact_principal(error_msg)) -- looks like redaction
                # and is not: it truncates the whole sentence to a few characters,
                # and every other consumer of that variable still holds the raw
                # identifier. The fix has to be at the interpolation.
                for arg in node.args:
                    if (isinstance(arg, ast.Name) and arg.id in tainted
                            and arg.id not in reported):
                        origin, names = tainted[arg.id]
                        if _classify_pii(
                            path, origin.lineno, segment(origin), names,
                            note=f' -- built here and logged at line {node.lineno}; '
                                 f'redact where the string is built, since anything '
                                 f'else that consumes it inherits the raw value',
                        ):
                            reported.add(arg.id)

                # Recognise redaction helpers by shape, not by name.
                #
                # This was a literal list. Every helper added since needed appending
                # to it, and each omission produced a false positive on
                # already-correct code: 'redact(' did not match redact_principal's
                # sibling redact_assignment_id, so six freshly-redacted call sites
                # still failed. Matching any redact*/...digest call closes the naming
                # trap the same way NON_IDENTITY_IDS closed the *_id one -- by
                # describing the category instead of listing its members.
                if REDACTION_CALL.search(seg):
                    continue

                _classify_pii(path, node.lineno, seg, _logged_identifiers(node))


RESPONSE_BODY = re.compile(r'\b(?:\w*response|resp|r)\s*\.\s*(?:text|content)\b')


def check_response_body_logging():
    """
    No log or print statement may emit a raw HTTP response body.

    The API this repository ships returns the CSV exports, so a response body can
    hold user emails and display names -- and on a partial or streamed failure it can
    hold export rows verbatim. Status code and request ID say what went wrong and are
    what Support asks for; neither carries personal data.

    This is separate from check_pii_logging because there is no identifier to
    classify: the leak is the body itself, and it looks like ordinary error handling.
    Three sites shipped this way, in the two places most likely to be copied -- the
    example API client and the post-deployment verification script.
    """
    for path in py_files():
        src = open(path).read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        lines = src.split('\n')
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if not _emits_output(fn):
                continue
            seg = '\n'.join(lines[node.lineno - 1:getattr(node, 'end_lineno', node.lineno)])
            match = RESPONSE_BODY.search(seg)
            if match:
                finding('pii', f'{rel(path)}:{node.lineno}',
                        f'emits {match.group(0)} -- a raw HTTP response body, which for '
                        f'this API can contain exported user emails and display names; '
                        f'log the status code and x-amzn-RequestId instead')


def check_documented_examples():
    """Every matching example in the docs must agree with validation.py."""
    lam = os.path.join(REPO, 'identity-center-remediation', 'lambda')
    sys.path.insert(0, lam)
    try:
        from validation import validate_assignment
    except Exception as e:
        finding('examples', 'identity-center-remediation/lambda/validation.py',
                f'cannot import validate_assignment: {e}')
        return
    # (application, group, regex, expected_compliant, where)
    cases = [
        ('Finance_PROD', 'Finance', None, True, 'README.md'),
        ('HR_PROD', 'Finance', None, False, 'README.md'),
        ('sagemaker_readonly', 'read', None, False, 'README.md'),
        ('MyApp-Developers', 'Developers', None, True, 'remediation/README.md'),
        ('MyApp-Developers', 'Develop', None, False, 'remediation/README.md'),
        ('MyApp-Dev', 'Dev-Team-AWS', r'^([^-]+)', True, 'remediation/README.md'),
        ('sagemaker_readonly', 'ReadOnly', None, True, 'blog'),
        ('sagemaker_readonly', 'Developer', None, False, 'blog'),
    ]
    for app, grp, rx, expected, where in cases:
        got = (validate_assignment(app, grp, rx) if rx
               else validate_assignment(app, grp)).is_compliant
        if got != expected:
            finding('examples', where,
                    f'documented example app={app!r} group={grp!r} claims '
                    f'{expected} but code returns {got}')


def check_doc_claims_against_code():
    """Deploy inputs named in the docs must exist in the CDK app."""
    src = ''
    for p in ('identity-center-remediation/bin/identity-center-app-monitor.ts',
              'identity-center-remediation/lib/identity-center-app-monitor-stack.ts'):
        fp = os.path.join(REPO, p)
        if os.path.exists(fp):
            src += open(fp).read()
    for name in ('IdentityCenterInstanceArn', 'ManagementAccountId',
                 'GroupNameRegex', 'enableAutoDeletion'):
        if name not in src:
            finding('docclaims', 'identity-center-remediation',
                    f'docs reference deploy input {name} which the CDK app does not define')


def check_relative_cd_in_docs():
    """`cd identity-center-remediation` after cd'ing into reporting cannot work."""
    for name in MD_FILES:
        path = os.path.join(REPO, name)
        if not os.path.exists(path):
            continue
        for i, line in enumerate(open(path).read().split('\n'), 1):
            if re.match(r'^\s*cd identity-center-(remediation|reporting)\s*$', line):
                finding('docpaths', f'{name}:{i}',
                        f'{line.strip()!r} is relative; if the reader already cd\'d '
                        f'into the sibling directory it fails')


REQUIREMENTS_FILES = [
    'identity-center-reporting/requirements.txt',
    'identity-center-reporting/tests/requirements-test.txt',
    'identity-center-remediation/lambda/requirements.txt',
]


def check_dependency_bounds():
    """
    Every >= dependency must carry an upper bound.

    A previous capping pass matched `name>=version` only at end of line, so it
    silently skipped every entry with a trailing comment and left freezegun,
    faker and hypothesis with no upper bound at all. The review caught it; this
    check means the next omission fails locally instead.
    """
    for name in REQUIREMENTS_FILES:
        path = os.path.join(REPO, name)
        if not os.path.exists(path):
            continue
        for lineno, line in enumerate(open(path).read().split('\n'), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            if re.match(r'^[A-Za-z0-9_.\-]+>=', stripped) and ',<' not in stripped:
                finding('deps', f'{name}:{lineno}',
                        f'{stripped.split()[0]} has a lower bound but no upper '
                        f'bound, so any future major release is accepted')


EMAIL = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
ALLOWED_DOMAINS = re.compile(
    r'@(example\.(com|org|net)|test|localhost|invalid|amazon\.com)$'
)
SKIP_DIRS = {'.git', '__pycache__', '.venv', 'node_modules', 'cdk.out', '.pytest_cache'}
SKIP_SUFFIXES = {'.png', '.svg', '.jpg', '.jpeg', '.gif', '.zip', '.ico', '.pdf'}


def check_reserved_domains():
    """
    Sample data must use RFC 2606 domains.

    Walks the tree in pure Python rather than shelling out to `git grep`. That
    call was the script's only subprocess use, and Bandit flagged it (B603) --
    reasonably, since a subprocess with a non-literal working directory is worth
    a second look. Removing it removes the finding rather than suppressing it,
    and drops the requirement that git be installed for the audit to run.
    """
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in SKIP_SUFFIXES:
                continue
            path = os.path.join(dirpath, name)
            try:
                with open(path, 'r', errors='ignore') as handle:
                    text = handle.read()
            except OSError:
                continue
            for addr in sorted(set(EMAIL.findall(text))):
                if not ALLOWED_DOMAINS.search(addr):
                    finding('domains', rel(path),
                            f'{addr} uses a registrable domain; '
                            f'RFC 2606 reserves example.com for documentation')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--baseline', metavar='FILE')
    ap.add_argument('--against', metavar='FILE')
    args = ap.parse_args()

    struct = structure()

    if args.baseline:
        with open(args.baseline, 'w') as f:
            json.dump(struct, f, indent=1, sort_keys=True)
        print(f'baseline written: {args.baseline} ({len(struct)} files)')
        return 0

    if args.against:
        old = json.load(open(args.against))
        for path, before in old.items():
            after = struct.get(path)
            if after is None:
                finding('structure', path, 'file disappeared since baseline')
                continue
            for kind in ('classes', 'functions', 'decorated'):
                lost = sorted(set(before[kind]) - set(after[kind]))
                if lost:
                    label = ('decorator attachment' if kind == 'decorated' else kind[:-1])
                    finding('structure', path,
                            f'{label} lost since baseline: {", ".join(lost)}')

    check_test_class_collectable()
    check_orphan_methods()
    check_anchors()
    check_pii_logging()
    check_response_body_logging()
    check_documented_examples()
    check_doc_claims_against_code()
    check_relative_cd_in_docs()
    check_dependency_bounds()
    check_reserved_domains()

    by_check = {}
    for f in findings:
        by_check.setdefault(f['check'], []).append(f)

    if not findings:
        print('adversarial audit: no findings')
        return 0

    print(f'adversarial audit: {len(findings)} finding(s)\n')
    for check in sorted(by_check):
        print(f'== {check} ({len(by_check[check])}) ==')
        for f in by_check[check]:
            print(f'   {f["path"]}\n      {f["detail"]}')
        print()
    return 1


if __name__ == '__main__':
    sys.exit(main())
