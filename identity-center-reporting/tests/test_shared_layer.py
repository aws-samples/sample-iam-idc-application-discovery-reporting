"""
Regression tests for the shared-modules Lambda layer.

The discovery functions import shared code as `from shared.x import y`. That code
used to be copied into each function's asset by a container bundling step, which
made Docker a hard prerequisite for `cdk synth` and `cdk deploy`. It now ships as
a layer instead.

Two things have to stay true for that to keep working:

1. The layer archive must place the modules at `python/shared/`. A layer is
   extracted to /opt and only /opt/python is on the Python path, so `shared/` at
   the archive root would import fine locally and fail at runtime.
2. Every function that imports shared code must have the layer attached.

These tests read the synthesized template, so run `cdk synth` first.
"""

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CDK_OUT = REPO_ROOT / "cdk.out"
TEMPLATE = CDK_OUT / "IamIdentityCenterDiscoveryStack-dev.template.json"

# Functions whose handlers import from shared/
SHARED_CONSUMERS = (
    "iam-identity-center-instance-scanner",
    "iam-identity-center-application-discovery",
    "iam-identity-center-assignment-discovery",
    "iam-identity-center-change-detection",
    "iam-identity-center-access-tracker",
    "iam-identity-center-csv-export",
)


def _template():
    if not TEMPLATE.exists():
        pytest.skip(f"{TEMPLATE.name} not found -- run 'cdk synth' first")
    return json.loads(TEMPLATE.read_text())


def _functions(template):
    out = {}
    for resource in template.get("Resources", {}).values():
        if resource.get("Type") != "AWS::Lambda::Function":
            continue
        name = resource.get("Properties", {}).get("FunctionName")
        if isinstance(name, str):
            out[name] = resource
    return out


def test_shared_layer_exists():
    """The stack must define exactly one shared-modules layer."""
    template = _template()
    layers = [
        r for r in template.get("Resources", {}).values()
        if r.get("Type") == "AWS::Lambda::LayerVersion"
    ]
    assert len(layers) == 1, f"expected one LayerVersion, found {len(layers)}"


@pytest.mark.parametrize("function_name", SHARED_CONSUMERS)
def test_function_has_shared_layer(function_name):
    """
    Each function importing shared code must have a layer attached.

    Without it the function raises ImportError on cold start, which surfaces only
    at runtime -- synth and deploy both succeed.
    """
    functions = _functions(_template())
    assert function_name in functions, f"{function_name} missing from template"
    layers = functions[function_name]["Properties"].get("Layers")
    assert layers, f"{function_name} has no layer attached; 'from shared.x' will fail"


def test_layer_stages_modules_under_python_dir():
    """
    The layer archive must contain python/shared/, not shared/ at the root.

    Only /opt/python is on the Lambda Python path. A root-level shared/ imports
    correctly in local tests and fails on the first cold start.
    """
    template = _template()
    layer = next(
        r for r in template["Resources"].values()
        if r.get("Type") == "AWS::Lambda::LayerVersion"
    )
    s3_key = layer["Properties"]["Content"]["S3Key"]
    asset_dir = CDK_OUT / f"asset.{s3_key.split('.')[0]}"
    if not asset_dir.is_dir():
        pytest.skip(f"staged asset {asset_dir.name} not present")

    assert (asset_dir / "python" / "shared").is_dir(), (
        f"{asset_dir.name} must contain python/shared/; "
        f"found top level: {sorted(p.name for p in asset_dir.iterdir())}"
    )
    assert not (asset_dir / "shared").exists(), (
        "shared/ must not sit at the archive root -- /opt/shared is not importable"
    )
    modules = {p.name for p in (asset_dir / "python" / "shared").glob("*.py")}
    for required in ("alerting.py", "models.py", "utils.py", "tracing.py"):
        assert required in modules, f"{required} missing from the layer"


def test_function_assets_do_not_duplicate_shared():
    """
    Function assets must not carry their own copy of shared/.

    Two copies means a fix applied to src/lambdas/shared/ can be silently
    shadowed by a stale duplicate inside a function asset.
    """
    template = _template()
    for name, resource in _functions(template).items():
        if name not in SHARED_CONSUMERS:
            continue
        s3_key = resource["Properties"]["Code"]["S3Key"]
        asset_dir = CDK_OUT / f"asset.{s3_key.split('.')[0]}"
        if not asset_dir.is_dir():
            continue
        assert not (asset_dir / "shared").exists(), (
            f"{name} asset still bundles its own shared/ copy"
        )


def test_no_container_bundling_in_stack():
    """
    Guard the Docker prerequisite from returning.

    BundlingOptions makes Docker required for synth and deploy. The shared modules
    are the reason it was there; a layer removes the need.
    """
    stack = (
        REPO_ROOT / "lib" / "stacks" / "iam_identity_center_discovery_stack.py"
    ).read_text()
    assert "BundlingOptions" not in stack, (
        "BundlingOptions reintroduces a Docker dependency for cdk synth/deploy"
    )
