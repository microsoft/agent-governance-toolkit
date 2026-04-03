# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
IATP CLI - Command Line Interface for Inter-Agent Trust Protocol

Provides developer tools to:
- Validate capability_manifest.json files
- Scan agents for trust scores
- Test IATP configurations
"""
import json
import sys

import click
import httpx

from iatp import __version__
from iatp.models import CapabilityManifest, RetentionPolicy, ReversibilityLevel, TrustLevel


@click.group()
@click.version_option(version=__version__, prog_name="iatp")
def cli():
    """
    IATP CLI - Inter-Agent Trust Protocol Developer Tools

    Validate manifests, scan agents, and test trust configurations.
    """
    pass


@cli.command()
@click.argument('manifest_path', type=click.Path(exists=True))
@click.option('--verbose', '-v', is_flag=True, help='Show detailed validation output')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def verify(manifest_path: str, verbose: bool, output_json: bool):
    """
    Validate a capability_manifest.json file.

    Checks for:
    - Valid JSON schema
    - Logical contradictions (e.g., retention: forever + privacy: strict)
    - Required fields
    - Enum value validity

    Example:
        iatp verify ./manifest.json
    """
    if not output_json:
        click.echo(f"🔍 Validating manifest: {manifest_path}")

    try:
        # Load the manifest file
        with open(manifest_path) as f:
            manifest_data = json.load(f)

        # Validate using Pydantic model
        try:
            manifest = CapabilityManifest(**manifest_data)
        except (ValueError, KeyError, PermissionError) as e:
            err_msg = "Manifest validation failed due to invalid schema or format."
            if output_json:
                print(json.dumps({"status": "fail", "error": err_msg, "type": "ValidationError"}, indent=2))
            else:
                click.echo("\n❌ Validation failed:", err=True)
                click.echo(f"   {err_msg}", err=True)
            sys.exit(1)
        except Exception:
            err_msg = "An internal error occurred while validating the manifest."
            if output_json:
                print(json.dumps({"status": "fail", "error": err_msg, "type": "InternalError"}, indent=2))
            else:
                click.echo(f"\n❌ Error: {err_msg}", err=True)
            sys.exit(1)

        # Perform logical contradiction checks
        errors = []
        warnings = []

        # Check 1: Retention policy vs. privacy expectations
        if manifest.privacy_contract.retention == RetentionPolicy.PERMANENT:
            if manifest.trust_level in [TrustLevel.VERIFIED_PARTNER, TrustLevel.STANDARD]:
                warnings.append(
                    "⚠️  Permanent retention with trusted agent - consider ephemeral or temporary"
                )

        # Check 2: Reversibility vs. trust level
        if manifest.capabilities.reversibility == ReversibilityLevel.NONE:
            if manifest.trust_level == TrustLevel.UNTRUSTED:
                errors.append(
                    "❌ Untrusted agent with no reversibility is a high-risk configuration"
                )

        # Check 3: Human review with high trust
        if manifest.privacy_contract.human_review:
            if manifest.trust_level == TrustLevel.VERIFIED_PARTNER:
                warnings.append(
                    "⚠️  Human review enabled for verified partner - may not be necessary"
                )

        # Calculate trust score
        trust_score = manifest.calculate_trust_score()

        if output_json:
            print(json.dumps({
                "status": "fail" if errors else "success",
                "agent_id": manifest.agent_id,
                "trust_level": manifest.trust_level.value,
                "trust_score": trust_score,
                "errors": errors,
                "warnings": warnings
            }, indent=2))
        else:
            if verbose:
                click.echo("\n📄 Raw manifest data:")
                click.echo(json.dumps(manifest_data, indent=2))

            # Display results
            if errors:
                click.echo(f"\n❌ Validation failed with {len(errors)} error(s):")
                for error in errors:
                    click.echo(f"   {error}")
                sys.exit(1)

            click.echo("\n✅ Schema validation passed")
            click.echo(f"   Agent ID: {manifest.agent_id}")
            click.echo(f"   Trust Level: {manifest.trust_level.value}")
            click.echo(f"   Trust Score: {trust_score}/10")

            if warnings:
                click.echo(f"\n⚠️  {len(warnings)} warning(s):")
                for warning in warnings:
                    click.echo(f"   {warning}")

            if verbose:
                click.echo("\n📊 Detailed Analysis:")
                click.echo(f"   Reversibility: {manifest.capabilities.reversibility.value}")
                click.echo(f"   Idempotency: {manifest.capabilities.idempotency}")
                if manifest.capabilities.rate_limit:
                    click.echo(f"   Rate Limit: {manifest.capabilities.rate_limit} req/min")
                if manifest.capabilities.sla_latency:
                    click.echo(f"   SLA Latency: {manifest.capabilities.sla_latency}")
                if manifest.capabilities.undo_window:
                    click.echo(f"   Undo Window: {manifest.capabilities.undo_window}")
                click.echo(f"   Retention: {manifest.privacy_contract.retention.value}")
                click.echo(f"   Human Review: {manifest.privacy_contract.human_review}")

            click.echo("\n✨ Manifest is valid and ready to use!")

    except FileNotFoundError:
        if output_json:
            print(json.dumps({"status": "fail", "error": f"File not found: {manifest_path}"}, indent=2))
        else:
            click.echo(f"❌ File not found: {manifest_path}", err=True)
        sys.exit(1)
    except json.JSONDecodeError as e:
        err_msg = "Invalid JSON structure provided."
        if output_json:
            print(json.dumps({"status": "fail", "error": err_msg}, indent=2))
        else:
            click.echo(f"❌ {err_msg}", err=True)
        sys.exit(1)
    except Exception as e:
        # Sanitize exception message to avoid leaking internal details
        is_known = isinstance(e, (FileNotFoundError, json.JSONDecodeError, ValueError, PermissionError))
        error_msg = "A validation or file access error occurred." if is_known else "An internal error occurred during verification."
        
        if output_json:
            print(json.dumps({
                "status": "fail",
                "error": error_msg,
                "type": "DataValidationError" if is_known else "InternalError"
            }, indent=2))
        else:
            click.echo(f"❌ Error: {error_msg}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('agent_url')
@click.option('--timeout', '-t', default=10, help='Request timeout in seconds')
@click.option('--verbose', '-v', is_flag=True, help='Show detailed scan output')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def scan(agent_url: str, timeout: int, verbose: bool, output_json: bool):
    """
    Scan an agent's capabilities endpoint and return a trust score.

    Pings the agent's /.well-known/agent-manifest endpoint and
    analyzes the exposed guarantees to calculate a trust score (0-100).

    Example:
        iatp scan http://localhost:8001
        iatp scan https://api.example.com/agent --timeout 30
    """
    if not output_json:
        click.echo(f"🔍 Scanning agent: {agent_url}")

    # Ensure URL has scheme
    if not agent_url.startswith(('http://', 'https://')):
        agent_url = f"http://{agent_url}"

    # Construct manifest endpoint URL
    manifest_url = f"{agent_url.rstrip('/')}/.well-known/agent-manifest"

    try:
        # Fetch the manifest
        with httpx.Client(timeout=timeout) as client:
            if verbose and not output_json:
                click.echo(f"📡 Fetching: {manifest_url}")

            response = client.get(manifest_url)
            response.raise_for_status()

            manifest_data = response.json()

            if verbose and not output_json:
                click.echo("\n📄 Received manifest:")
                click.echo(json.dumps(manifest_data, indent=2))

        # Parse into CapabilityManifest
        manifest = CapabilityManifest(**manifest_data)

        # Calculate trust score (0-10 scale, convert to 0-100)
        trust_score_10 = manifest.calculate_trust_score()
        trust_score_100 = int(trust_score_10 * 10)

        # Determine risk level
        if trust_score_100 >= 80:
            risk_level = "🟢 LOW"
            risk_emoji = "✅"
        elif trust_score_100 >= 50:
            risk_level = "🟡 MEDIUM"
            risk_emoji = "⚠️"
        else:
            risk_level = "🔴 HIGH"
            risk_emoji = "❌"

        if output_json:
            print(json.dumps({
                "status": "success",
                "agent_id": manifest.agent_id,
                "trust_score": trust_score_100,
                "risk_level": risk_level.strip().split()[-1],
                "trust_level": manifest.trust_level.value,
                "reversibility": manifest.capabilities.reversibility.value,
                "retention": manifest.privacy_contract.retention.value,
                "manifest": manifest_data if verbose else None
            }, indent=2))
        else:
            # Display results
            click.echo(f"\n{risk_emoji} Trust Score: {trust_score_100}/100 ({risk_level})")
            click.echo("\n📊 Agent Profile:")
            click.echo(f"   Agent ID: {manifest.agent_id}")
            click.echo(f"   Trust Level: {manifest.trust_level.value}")
            click.echo(f"   Reversibility: {manifest.capabilities.reversibility.value}")
            click.echo(f"   Data Retention: {manifest.privacy_contract.retention.value}")

            # Security indicators
            click.echo("\n🔒 Security Indicators:")
            click.echo(f"   {'✅' if manifest.capabilities.idempotency else '❌'} Idempotent operations")
            click.echo(f"   {'✅' if manifest.capabilities.reversibility != ReversibilityLevel.NONE else '❌'} Reversibility support")
            click.echo(f"   {'✅' if manifest.privacy_contract.retention != RetentionPolicy.PERMANENT else '❌'} Limited data retention")
            click.echo(f"   {'⚠️' if manifest.privacy_contract.human_review else '✅'} {'Human review enabled' if manifest.privacy_contract.human_review else 'Automated processing'}")

            # Recommendations
            if trust_score_100 < 50:
                click.echo("\n⚠️  Recommendations:")
                click.echo("   • This agent has a low trust score")
                click.echo("   • Use X-User-Override: true header to proceed")
                click.echo("   • Avoid sending sensitive data")
                click.echo("   • Monitor quarantine logs")

            if verbose:
                click.echo("\n📈 Performance Guarantees:")
                if manifest.capabilities.rate_limit:
                    click.echo(f"   Rate Limit: {manifest.capabilities.rate_limit} req/min")
                if manifest.capabilities.sla_latency:
                    click.echo(f"   SLA Latency: {manifest.capabilities.sla_latency}")

    except Exception as e:
        # Sanitize error message based on exception type to prevent info leakage
        is_known = isinstance(e, (httpx.RequestError, json.JSONDecodeError, ValueError, PermissionError))
        err_msg = "An error occurred fetching or validating the agent manifest." if is_known else "An internal error occurred during agent scan"
        
        if output_json:
            print(json.dumps({
                "status": "fail",
                "error": err_msg,
                "type": "ScanDataError" if is_known else "InternalError"
            }, indent=2))
        else:
            click.echo(f"\n❌ Scan error: {err_msg}", err=True)
            if verbose and not is_known:
                import traceback
                click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


@cli.command()
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def version(output_json: bool):
    """Show IATP version information."""
    if output_json:
        print(json.dumps({
            "name": "IATP CLI",
            "version": __version__,
            "description": "Inter-Agent Trust Protocol",
            "url": "https://github.com/microsoft/agent-governance-toolkit"
        }, indent=2))
    else:
        click.echo(f"IATP CLI v{__version__}")
        click.echo("Inter-Agent Trust Protocol")
        click.echo("https://github.com/microsoft/agent-governance-toolkit")


if __name__ == '__main__':
    cli()
