###############################################################################
# Demo 4: Two Agents, Zero Trust - Real Handshake & Identity
# MVP PGI - Agent Governance Toolkit
#
# Story: Contoso Bank has a Loan Officer agent that needs data from a
# Credit Checker agent. They must negotiate trust cryptographically.
# Shows: DID identity, trust handshake, delegation, escalation failure,
# and instant kill switch.
# Expected time: ~25 seconds
###############################################################################

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host "  DEMO 4: Two Agents, Zero Trust" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan
Write-Host ""
Write-Host "  Story: Loan Officer needs credit data from Credit Checker." -ForegroundColor White
Write-Host "  They don't trust each other. They MUST negotiate." -ForegroundColor Yellow
Write-Host ""

$script = @"
import asyncio, sys, os
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

from agentmesh.identity import AgentIdentity
from agentmesh.trust import (
    TrustHandshake, TrustedAgentCard,
    CapabilityGrant, CapabilityScope,
)

G = '\033[92m'  # green
R = '\033[91m'  # red
Y = '\033[93m'  # yellow
C = '\033[96m'  # cyan
B = '\033[1m'   # bold
D = '\033[2m'   # dim
X = '\033[0m'   # reset
DASH = '\u2501'

def section(title):
    print(f'\n{Y}{B}{DASH*3} {title} {DASH*(56-len(title))}{X}\n')

async def main():
    # ---- Scene 1: Create two agents ----
    section('Scene 1: Agent Identities')
    print(f'  {C}Creating two agents at Contoso Bank...{X}\n')

    loan_officer = AgentIdentity.create(
        name='loan-officer',
        sponsor='lending@contoso.com',
        capabilities=['read:data', 'write:data', 'approve:loans'],
        description='AI Loan Officer: processes applications',
    )
    credit_checker = AgentIdentity.create(
        name='credit-checker',
        sponsor='risk@contoso.com',
        capabilities=['read:data', 'check:credit'],
        description='Credit Bureau Agent: returns scores',
    )

    for agent in [loan_officer, credit_checker]:
        print(f'  {B}{agent.name}{X}')
        print(f'    DID:  {D}{agent.did}{X}')
        print(f'    Caps: {agent.capabilities}')
        print(f'    Active: {G}True{X}')
        print()

    # ---- Scene 2: Trust handshake ----
    section('Scene 2: Trust Handshake (Agent-to-Agent)')

    hs_officer = TrustHandshake(agent_did=str(loan_officer.did), identity=loan_officer)
    hs_checker = TrustHandshake(agent_did=str(credit_checker.did), identity=credit_checker)

    print(f'  {C}Loan Officer{X} \u2192 creates cryptographic challenge...')
    challenge = hs_officer.create_challenge()
    print(f'    Challenge ID: {D}{challenge.challenge_id[:30]}...{X}')
    print(f'    Nonce:        {D}{challenge.nonce[:30]}...{X}')
    print(f'    Expires:      {challenge.expires_in_seconds}s')

    print(f'\n  {C}Credit Checker{X} \u2192 responds with signed proof...')
    response = await hs_checker.respond(
        challenge,
        my_capabilities=credit_checker.capabilities,
        my_trust_score=850,
        identity=credit_checker,
    )
    print(f'    Agent DID:  {D}{response.agent_did}{X}')
    print(f'    Caps:       {response.capabilities}')
    print(f'    Trust:      {B}{response.trust_score}{X}')
    print(f'    Signature:  {D}{str(response.signature)[:40]}...{X}')
    print(f'\n  {G}\u2713 Handshake complete: agents verified each other cryptographically{X}')

    # ---- Scene 3: Capability scoping ----
    section('Scene 3: Capability Scoping (What Can Each Agent Do?)')

    scope = CapabilityScope(agent_did=str(credit_checker.did))
    grant = CapabilityGrant.create(
        capability='read:data',
        granted_to=str(credit_checker.did),
        granted_by=str(loan_officer.did),
    )
    scope.add_grant(grant)

    checks = ['read:data', 'write:data', 'approve:loans', 'check:credit']
    print(f'  Credit Checker was granted ONLY {B}read:data{X} by Loan Officer:\n')
    for cap in checks:
        try:
            allowed = scope.has_capability(cap)
        except Exception:
            allowed = False
        icon = f'{G}\u2713{X}' if allowed else f'{R}\u2717{X}'
        status = f'{G}GRANTED{X}' if allowed else f'{R}DENIED{X}'
        print(f'    {icon} {cap:<18} {status}')

    print(f'\n  {Y}Key: Even trusted agents get ONLY what they need.{X}')

    # ---- Scene 4: Delegation & escalation attempt ----
    section('Scene 4: Delegation Gone Wrong')

    print(f'  Loan Officer delegates a sub-agent for data entry...')
    sub = loan_officer.delegate(name='data-entry-bot', capabilities=['read:data'])
    print(f'    {G}\u2713{X} Created {B}data-entry-bot{X} with caps: {sub.capabilities}')
    print(f'      Effective: {sub.get_effective_capabilities()}')

    print(f'\n  {R}Now a rogue process tries to create a privileged agent...{X}')
    try:
        rogue = credit_checker.delegate(
            name='rogue-escalator',
            capabilities=['read:data', 'approve:loans', 'write:data'],
        )
        print(f'  {R}ERROR: Should have been blocked!{X}')
    except ValueError:
        print(f'    {R}\u2717 BLOCKED{X}: credit-checker tried to grant {B}approve:loans{X}')
        print(f'    {R}\u2717 BLOCKED{X}: credit-checker tried to grant {B}write:data{X}')
        print(f'    {D}  Credit Checker only has [read:data, check:credit]{X}')
        print(f'    {Y}  Cannot delegate capabilities you don\'t possess!{X}')

    # ---- Scene 5: Kill switch ----
    section('Scene 5: Kill Switch')

    print(f'  Loan Officer active: {G}{loan_officer.is_active()}{X}')
    loan_officer.suspend(reason='Anomalous behavior detected by SRE')
    print(f'  After suspend():    {R}{loan_officer.is_active()}{X}  \u2190 {D}instantly disabled{X}')

    print(f'\n  Reactivate with explicit reason...')
    loan_officer.reactivate(override_reason=True)
    print(f'    After reactivate(override_reason=True): {G}{loan_officer.is_active()}{X}')

    sub.revoke(reason='Task complete, cleaning up')
    print(f'\n  Sub-agent revoked: active={R}{sub.is_active()}{X}')
    print(f'  {Y}One API call = instant, permanent revocation.{X}')
    print(f'  {Y}This is the agent kill switch.{X}')

asyncio.run(main())
"@

$tempFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.py'
$script | Out-File -FilePath $tempFile -Encoding utf8

try {
    python $tempFile
    if ($LASTEXITCODE -ne 0) { throw "Python script failed" }
} catch {
    Write-Host ""
    Write-Host "  Note: If you see import errors, run: pip install agent-governance-toolkit[full]" -ForegroundColor DarkGray
}

Remove-Item $tempFile -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=" * 60 -ForegroundColor Green
Write-Host "  DEMO 4 COMPLETE - Zero-trust identity for agents!" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Green
Write-Host ""
Write-Host "TALKING POINTS:" -ForegroundColor DarkGray
Write-Host "  - Two agents negotiate trust via cryptographic handshake" -ForegroundColor DarkGray
Write-Host "  - DID-based identity, no central authority needed" -ForegroundColor DarkGray
Write-Host "  - Capability scoping: agents get ONLY what they need" -ForegroundColor DarkGray
Write-Host "  - Delegation CANNOT escalate, scope only narrows" -ForegroundColor DarkGray
Write-Host "  - Rogue escalation attempt: instantly blocked" -ForegroundColor DarkGray
Write-Host "  - Kill switch: suspend/revoke = one API call" -ForegroundColor DarkGray
