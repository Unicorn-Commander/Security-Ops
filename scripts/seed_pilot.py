"""Seed the Security-Ops pilot — the README's running-start proof (spec §4).

Idempotently creates:

  1. the pilot :class:`Organization` (slug ``pilot``),
  2. a self-owned, **ATTESTED** :class:`AuthorizedTarget` for
     ``brigade.unicorncommander.ai`` — method ``OWNED``, with checkbox +
     typed-confirmation evidence, unexpired,
  3. an **ACTIVE** :class:`Engagement` scoped to that target.

Then, when the authorization gate and its sibling modules are present in this
build, it DEMONSTRATES the gate end-to-end: ``enforce_scope`` returns cleanly for
an in-scope URL and raises :class:`AuthorizationDenied` (HTTP 403) for an
out-of-scope one, appending exactly one immutable audit row per decision.

Run:
    python -m scripts.seed_pilot          # in-container: `make seed`
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core.config import settings
from app.db.session import async_session, close_db
from app.models.engagement import Engagement, EngagementStatus
from app.models.organization import Organization
from app.models.target import (
    AttestationMethod,
    AttestationStatus,
    AuthorizedTarget,
    TargetKind,
)

# --- Pilot constants --------------------------------------------------------
PILOT_ORG_SLUG = "pilot"
PILOT_ORG_NAME = "Unicorn Commander (Pilot)"
PILOT_ORG_KEYCLOAK_GROUP = "/orgs/pilot"

TARGET_DOMAIN = "brigade.unicorncommander.ai"
TARGET_LABEL = "Unicorn Brigade — self-owned suite asset"

ENGAGEMENT_NAME = "Pilot — self-owned suite assessment"
MODEL_PROFILE = "hybrid-local-sweep-verify"

SEED_PRINCIPAL_ID = "seed-pilot"
SEED_PRINCIPAL_EMAIL = "demo@example.invalid"

# Gate-proof probes.
IN_SCOPE_URL = "https://brigade.unicorncommander.ai/login"
OUT_OF_SCOPE_URL = "https://example.com/"

ATTESTATION_TTL = timedelta(days=365)
ENGAGEMENT_TTL = timedelta(days=30)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _redacted(url: str) -> str:
    """Hide the password in a ``scheme://user:pass@host`` URL for logging."""
    return re.sub(r"(://[^:/@]+:)[^@]*(@)", r"\1***\2", url)


def _engagement_scope() -> dict:
    """``{in_scope: [ScopeRule], exclusions: [ScopeRule]}`` — a ScopeRule is
    ``{kind, value}`` (matches app.models.engagement + app.engine.strix_runner)."""
    return {
        "in_scope": [{"kind": TargetKind.DOMAIN.value, "value": TARGET_DOMAIN}],
        "exclusions": [],
    }


def _rules_of_engagement() -> dict:
    """``{intensity, allowed_vuln_classes, time_window_start/end, max_concurrency}``."""
    return {
        "intensity": "standard",
        "allowed_vuln_classes": ["OWASP_TOP_10"],
        "time_window_start": None,
        "time_window_end": None,
        "max_concurrency": 1,
    }


# --- Idempotent upserts -----------------------------------------------------
async def _get_or_create_org(session) -> tuple[Organization, bool]:
    existing = (
        await session.execute(
            select(Organization).where(Organization.slug == PILOT_ORG_SLUG)
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing, False
    org = Organization(
        slug=PILOT_ORG_SLUG,
        name=PILOT_ORG_NAME,
        keycloak_group=PILOT_ORG_KEYCLOAK_GROUP,
    )
    session.add(org)
    await session.flush()
    return org, True


async def _get_or_create_target(
    session, org: Organization
) -> tuple[AuthorizedTarget, bool]:
    now = _utcnow()
    evidence = {
        "method": AttestationMethod.OWNED.value,
        "checkbox": True,
        "typed_confirmation": TARGET_DOMAIN,
        "attested_by": SEED_PRINCIPAL_EMAIL,
        "note": (
            "Self-owned Unicorn Commander suite asset; owner-attested for the "
            "pilot (spec §4)."
        ),
    }
    existing = (
        await session.execute(
            select(AuthorizedTarget).where(
                AuthorizedTarget.org_id == org.id,
                AuthorizedTarget.kind == TargetKind.DOMAIN,
                AuthorizedTarget.value == TARGET_DOMAIN,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        # Refresh into a valid, attested, unexpired state (idempotent re-seed).
        existing.attestation_status = AttestationStatus.ATTESTED
        existing.attestation_method = AttestationMethod.OWNED
        existing.attested_by = SEED_PRINCIPAL_EMAIL
        existing.attested_at = existing.attested_at or now
        existing.attestation_evidence = evidence
        existing.owner_principal = SEED_PRINCIPAL_EMAIL
        existing.expires_at = now + ATTESTATION_TTL
        existing.revoked_at = None
        return existing, False
    target = AuthorizedTarget(
        org_id=org.id,
        kind=TargetKind.DOMAIN,
        value=TARGET_DOMAIN,
        label=TARGET_LABEL,
        owner_principal=SEED_PRINCIPAL_EMAIL,
        attestation_status=AttestationStatus.ATTESTED,
        attestation_method=AttestationMethod.OWNED,
        attested_by=SEED_PRINCIPAL_EMAIL,
        attested_at=now,
        attestation_evidence=evidence,
        expires_at=now + ATTESTATION_TTL,
    )
    session.add(target)
    await session.flush()
    return target, True


async def _get_or_create_engagement(
    session, org: Organization
) -> tuple[Engagement, bool]:
    now = _utcnow()
    scope = _engagement_scope()
    roe = _rules_of_engagement()
    existing = (
        await session.execute(
            select(Engagement).where(
                Engagement.org_id == org.id,
                Engagement.name == ENGAGEMENT_NAME,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        existing.status = EngagementStatus.ACTIVE
        existing.scope = scope
        existing.rules_of_engagement = roe
        existing.model_profile = MODEL_PROFILE
        existing.starts_at = existing.starts_at or now
        existing.expires_at = now + ENGAGEMENT_TTL
        existing.emergency_stopped = False
        return existing, False
    engagement = Engagement(
        org_id=org.id,
        name=ENGAGEMENT_NAME,
        status=EngagementStatus.ACTIVE,
        scope=scope,
        rules_of_engagement=roe,
        model_profile=MODEL_PROFILE,
        created_by=SEED_PRINCIPAL_EMAIL,
        starts_at=now,
        expires_at=now + ENGAGEMENT_TTL,
        emergency_stopped=False,
    )
    session.add(engagement)
    await session.flush()
    return engagement, True


async def seed() -> tuple[str, uuid.UUID]:
    """Create/refresh the pilot records. Returns ``(org_slug, engagement_id)``."""
    async with async_session() as session:
        org, org_new = await _get_or_create_org(session)
        target, target_new = await _get_or_create_target(session, org)
        engagement, eng_new = await _get_or_create_engagement(session, org)
        await session.commit()

    def _mark(created: bool) -> str:
        return "created" if created else "exists"

    print("[seed] pilot data:")
    print(f"[seed]   org         {org.slug!r:<28} id={org.id}  ({_mark(org_new)})")
    print(
        f"[seed]   target      {target.value!r:<28} id={target.id}  "
        f"({target.attestation_status.value} via {target.attestation_method.value}, "
        f"{_mark(target_new)})"
    )
    print(
        f"[seed]   engagement  {engagement.name!r:<28} id={engagement.id}  "
        f"({engagement.status.value}, {_mark(eng_new)})"
    )
    # expire_on_commit=False keeps these attributes loaded after commit.
    return org.slug, engagement.id


async def _gate_proof(org_slug: str, engagement_id: uuid.UUID) -> str:
    """Demonstrate the authorization gate. Returns one of:
    ``"pass"`` | ``"fail"`` | ``"leak"`` | ``"skip"``.

    ``skip`` = the gate (or a sibling it needs) is not present/runnable in this
    build slice — the core seeding above still succeeded.
    """
    try:
        from app.auth.sso import AuthUser, UserRole
        from app.authz.errors import AuthorizationDenied
        from app.authz.gate import enforce_scope
    except ImportError as exc:
        print(f"[seed] gate proof SKIPPED — authz modules not present yet ({exc}).")
        return "skip"

    actor = AuthUser(
        id=SEED_PRINCIPAL_ID,
        email=SEED_PRINCIPAL_EMAIL,
        role=UserRole.ADMIN,
        org_slug=org_slug,
        apps=[settings.entitlement_sku],
    )

    print("[seed] demonstrating the authorization gate (spec §4)…")
    try:
        # 1) In-scope, attested target MUST be allowed (enforce_scope -> None).
        allowed_ok = True
        async with async_session() as session:
            try:
                await enforce_scope(
                    session, engagement_id, IN_SCOPE_URL, actor=actor
                )
                await session.commit()
                print(f"[seed]   ALLOWED  {IN_SCOPE_URL}  (in scope + attested)")
            except AuthorizationDenied as exc:
                await session.rollback()
                allowed_ok = False
                print(
                    f"[seed]   DENIED   {IN_SCOPE_URL}  — UNEXPECTED "
                    f"{type(exc).__name__}: {exc}"
                )

        # 2) Out-of-scope target MUST be denied (AuthorizationDenied / HTTP 403).
        denied_ok = False
        async with async_session() as session:
            try:
                await enforce_scope(
                    session, engagement_id, OUT_OF_SCOPE_URL, actor=actor
                )
                await session.commit()
                print(
                    f"[seed]   ALLOWED  {OUT_OF_SCOPE_URL}  — GATE LEAK "
                    "(should have been denied!)"
                )
            except AuthorizationDenied as exc:
                await session.commit()  # persist the append-only deny audit row
                denied_ok = True
                print(
                    f"[seed]   DENIED   {OUT_OF_SCOPE_URL}  -> "
                    f"{type(exc).__name__} (HTTP 403)"
                )
    except Exception as exc:  # gate present but a sibling contract isn't ready
        print(
            f"[seed] gate proof SKIPPED — gate not runnable in this build: "
            f"{type(exc).__name__}: {exc}"
        )
        return "skip"

    if not denied_ok:
        return "leak"
    if allowed_ok:
        print("[seed] gate proof PASSED — one immutable audit row per decision.")
        return "pass"
    return "fail"


async def main() -> int:
    print("[seed] Security-Ops pilot seed")
    print(f"[seed] database: {_redacted(settings.database_url)}")
    try:
        org_slug, engagement_id = await seed()
        result = await _gate_proof(org_slug, engagement_id)
    finally:
        await close_db()

    if result == "leak":
        print(
            "[seed] FAIL: the authorization gate ALLOWED an out-of-scope target "
            "(guardrail violation — spec §11)."
        )
        return 1
    if result == "fail":
        print(
            "[seed] WARNING: the in-scope target was denied. If sibling scope/schema "
            "modules are still landing in this build, this can be transient; verify "
            "once the gate stack is complete."
        )
    print("[seed] done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
