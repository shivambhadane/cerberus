"""Domains a user claims, and the proof that they control them.

A claim is just a row. Only a *verified* domain can be scanned (`core.ownership.check_scan_allowed`),
and verification means publishing a secret in the domain's DNS (`core.verification`).

Every route is scoped to the caller. A domain owned by someone else is answered exactly like one that
does not exist, so the API cannot be used to discover what other people have claimed.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import providers
from api.deps import ApiError, current_user, get_session
from api.schemas import (
    DomainCreate,
    DomainList,
    DomainOut,
    ProviderTargetRequest,
    ProviderVerifyRequest,
    TestbedList,
    TestbedTargetOut,
    VerificationInstructions,
    VerifyResult,
)
from core import provider_service, verification
from core.models import Domain, User, utcnow
from core.ownership import OwnershipError, normalize_domain
from core.throttle import FailureLimiter, Throttled

router = APIRouter(prefix="/api/v1/domains", tags=["domains"])

MAX_DOMAINS_PER_USER = 25
# Each verification is a DNS lookup made from our server; bound how many one account can ask for.
verify_limiter = FailureLimiter(max_failures=30, window_seconds=3600)


def reset_limiters() -> None:
    verify_limiter._failures.clear()


def _out(domain: Domain) -> DomainOut:
    on_platform = domain.verification_method in providers.PROVIDER_NAMES
    instructions = None
    if not on_platform:  # a DNS record only means something for a DNS-verified target
        name, value = verification.challenge_record(domain.domain, domain.verification_token)
        instructions = VerificationInstructions(
            method=domain.verification_method, record_name=name, record_value=value
        )
    return DomainOut(
        id=domain.id,
        domain=domain.domain,
        verification_status=domain.verification_status,
        verification_method=domain.verification_method,
        verified_at=domain.verified_at,
        created_at=domain.created_at,
        verification=instructions,
        provider=domain.provider,
        provider_project_id=domain.provider_project_id,
    )


def _owned(session: Session, user: User, domain_id: str) -> Domain:
    domain = session.get(Domain, domain_id)
    if domain is None or domain.user_id != user.id:
        raise ApiError(404, "not_found", "No such domain.")
    return domain


@router.post("", response_model=DomainOut, status_code=201)
def add_domain(
    payload: DomainCreate,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> DomainOut:
    try:
        name = normalize_domain(payload.domain)
    except OwnershipError as exc:
        raise ApiError(400, "invalid_domain", str(exc)) from None

    platform = providers.platform_for_hostname(name)
    if platform is not None:
        label = providers.get_provider(platform).label
        suffix = providers.PLATFORM_SUFFIXES[platform]
        raise ApiError(
            400, "use_provider",
            f"Addresses on {suffix} cannot be verified with a DNS record, because you cannot publish one "
            f"there. Connect your {label} account and choose the project instead.",
        )

    count = session.scalar(select(func.count()).select_from(Domain).where(Domain.user_id == user.id)) or 0
    if count >= MAX_DOMAINS_PER_USER:
        raise ApiError(400, "domain_limit", f"You can add up to {MAX_DOMAINS_PER_USER} domains.")
    if session.scalar(select(Domain.id).where(Domain.user_id == user.id, Domain.domain == name)):
        raise ApiError(409, "domain_exists", f"You have already added {name}.")

    domain = Domain(user_id=user.id, domain=name)  # method dns_txt, status pending, fresh token
    session.add(domain)
    try:
        session.flush()
    except IntegrityError:
        raise ApiError(409, "domain_exists", f"You have already added {name}.") from None
    return _out(domain)


@router.get("", response_model=DomainList)
def list_domains(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> DomainList:
    domains = session.scalars(
        select(Domain).where(Domain.user_id == user.id).order_by(Domain.created_at.desc(), Domain.domain)
    ).all()
    return DomainList(total=len(domains), domains=[_out(d) for d in domains])


SANCTIONED_TESTBEDS: dict[str, dict] = {
    "testasp": {
        "id": "testasp",
        "name": "Acunetix TestASP",
        "category": "public",
        "domain": "testasp.vulnweb.com",
        "url": "http://testasp.vulnweb.com",
        "ports": [80],
        "description": (
            "Classic ASP / Microsoft IIS intentionally vulnerable web application "
            "maintained by Acunetix specifically for scanner benchmarking."
        ),
        "vulnerabilities": ["SQL Injection", "Path Traversal", "ASP Source Disclosure", "XSS"],
        "tags": ["Public Benchmark", "ASP / IIS", "Sanctioned"],
        "provider_disclaimer": "Maintained by Acunetix for scanner testing & security education.",
    },
    "demo-testfire": {
        "id": "demo-testfire",
        "name": "IBM Altoro Mutual",
        "category": "public",
        "domain": "demo.testfire.net",
        "url": "http://demo.testfire.net",
        "ports": [80],
        "description": (
            "Simulated online banking portal created by Watchfire / IBM "
            "featuring deliberate web application security flaws."
        ),
        "vulnerabilities": [
            "SQL Injection",
            "Administrative Bypass",
            "Cross-Site Scripting (XSS)",
            "Session Fixation",
        ],
        "tags": ["Public Benchmark", "Banking Portal", "Sanctioned"],
        "provider_disclaimer": "Maintained for public security testing, scanner evaluation & education.",
    },
    "testphp": {
        "id": "testphp",
        "name": "Acunetix TestPHP",
        "category": "public",
        "domain": "testphp.vulnweb.com",
        "url": "http://testphp.vulnweb.com",
        "ports": [80],
        "description": (
            "Intentionally vulnerable PHP / MySQL web application provided by "
            "Acunetix for testing vulnerability scanners."
        ),
        "vulnerabilities": [
            "SQL Injection",
            "Cross-Site Scripting (XSS)",
            "Directory Traversal",
            "File Upload",
        ],
        "tags": ["Public Benchmark", "PHP / MySQL", "Sanctioned"],
        "provider_disclaimer": (
            "Maintained by Acunetix for scanner testing. (Note: subject to periodic public server outages)."
        ),
    },
    "apache-lab": {
        "id": "apache-lab",
        "name": "Cerberus Apache 2.4.49/50 Lab",
        "category": "docker",
        "domain": "127.0.0.1",
        "url": "http://127.0.0.1:18081",
        "ports": [18081, 18082],
        "docker_command": "docker compose -f lab/docker-compose.yml up -d",
        "docker_teardown": "docker compose -f lab/docker-compose.yml down",
        "description": (
            "Built-in dual Apache lab running Apache 2.4.49 (port 18081) and Apache 2.4.50 (port 18082) "
            "with vulnerable CGI configurations."
        ),
        "vulnerabilities": [
            "CVE-2021-41773 (Path Traversal / RCE, CISA KEV)",
            "CVE-2021-42013 (Incomplete fix, CISA KEV)",
        ],
        "tags": ["Docker Lab", "Localhost", "CISA KEV"],
        "provider_disclaimer": "Controlled repeatable Docker testbed bound to 127.0.0.1.",
    },
    "juice-shop": {
        "id": "juice-shop",
        "name": "OWASP Juice Shop",
        "category": "docker",
        "domain": "127.0.0.1",
        "url": "http://127.0.0.1:3000",
        "ports": [3000],
        "docker_command": "docker run -d --name cerberus-juice-shop -p 3000:3000 bkimminich/juice-shop",
        "docker_teardown": "docker rm -f cerberus-juice-shop",
        "description": (
            "The most modern and sophisticated intentionally vulnerable web application created by OWASP, "
            "encompassing the entire OWASP Top 10."
        ),
        "vulnerabilities": [
            "OWASP Top 10",
            "SQL Injection",
            "Broken Authentication",
            "Sensitive Data Exposure",
            "XSS",
            "Security Misconfiguration",
        ],
        "tags": ["Docker Lab", "OWASP Top 10", "Node.js / Angular"],
        "provider_disclaimer": "Official OWASP project run locally in Docker.",
    },
    "dvwa": {
        "id": "dvwa",
        "name": "Damn Vulnerable Web App (DVWA)",
        "category": "docker",
        "domain": "127.0.0.1",
        "url": "http://127.0.0.1:8080",
        "ports": [8080],
        "docker_command": "docker run -d --name cerberus-dvwa -p 8080:80 vulnerables/web-dvwa",
        "docker_teardown": "docker rm -f cerberus-dvwa",
        "description": (
            "Classic PHP/MySQL web application deliberately vulnerable to web security flaws, "
            "ideal for benchmarking vulnerability scanners."
        ),
        "vulnerabilities": [
            "SQL Injection",
            "Blind SQLi",
            "Command Execution",
            "CSRF",
            "File Inclusion",
            "XSS",
        ],
        "tags": ["Docker Lab", "PHP / MySQL", "Classic Testbed"],
        "provider_disclaimer": "Deliberately vulnerable environment run locally in Docker.",
    },
}


@router.get("/testbeds", response_model=TestbedList)
def list_testbeds(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> TestbedList:
    """List available sanctioned testbeds and Docker labs, annotated with whether
    the current user already added and verified them."""
    user_domains = {
        d.domain: d.id
        for d in session.scalars(
            select(Domain).where(Domain.user_id == user.id, Domain.verification_status == "verified")
        ).all()
    }
    result = []
    for tid, info in SANCTIONED_TESTBEDS.items():
        domain_name = info["domain"]
        already_added = domain_name in user_domains
        domain_id = user_domains.get(domain_name)
        result.append(
            TestbedTargetOut(
                id=tid,
                name=info["name"],
                category=info["category"],
                domain=domain_name,
                url=info.get("url"),
                ports=info.get("ports", []),
                docker_command=info.get("docker_command"),
                docker_teardown=info.get("docker_teardown"),
                description=info["description"],
                vulnerabilities=info.get("vulnerabilities", []),
                tags=info.get("tags", []),
                provider_disclaimer=info.get("provider_disclaimer"),
                already_added=already_added,
                domain_id=domain_id,
            )
        )
    return TestbedList(total=len(result), testbeds=result)


@router.post("/testbeds/{target_id}", response_model=DomainOut)
def add_testbed_target(
    target_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> DomainOut:
    """Add a sanctioned testbed or local Docker lab as an immediately verified target."""
    info = SANCTIONED_TESTBEDS.get(target_id)
    if not info:
        raise ApiError(404, "not_found", f"Unknown testbed '{target_id}'.")

    target_domain = info["domain"]

    domain = session.scalar(
        select(Domain).where(Domain.user_id == user.id, Domain.domain == target_domain)
    )
    if domain is None:
        count = session.scalar(select(func.count()).select_from(Domain).where(Domain.user_id == user.id)) or 0
        if count >= MAX_DOMAINS_PER_USER:
            raise ApiError(400, "domain_limit", f"You can add up to {MAX_DOMAINS_PER_USER} domains.")
        domain = Domain(
            user_id=user.id,
            domain=target_domain,
            verification_method="testbed",
            verification_status="verified",
            verified_at=utcnow(),
        )
        session.add(domain)
    else:
        domain.verification_status = "verified"
        domain.verified_at = utcnow()
        domain.verification_method = "testbed"

    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise ApiError(409, "domain_exists", f"{target_domain} is already added.") from None

    return _out(domain)


@router.get("/{domain_id}", response_model=DomainOut)
def get_domain(
    domain_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> DomainOut:
    return _out(_owned(session, user, domain_id))


@router.post("/{domain_id}/verify", response_model=VerifyResult)
def verify_domain(
    domain_id: str,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> VerifyResult:
    """Look for the verification record now. A missing record is a normal answer (200,
    `verified: false`), not an error: DNS changes take time and the owner will try again."""
    domain = _owned(session, user, domain_id)
    if domain.verification_method in providers.PROVIDER_NAMES:
        raise ApiError(
            400, "wrong_method",
            f"{domain.domain} is verified through a connected {domain.verification_method.title()} account, "
            "not a DNS record.",
        )
    if domain.verification_status == "verified":
        return VerifyResult(
            verified=True, reason="verified", domain=_out(domain),
            detail=f"{domain.domain} is already verified.",
        )

    try:
        verify_limiter.check(user.id)
    except Throttled as exc:
        raise ApiError(
            429, "too_many_attempts",
            f"Too many verification attempts. Try again in {exc.retry_after} seconds.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None
    verify_limiter.record_failure(user.id)

    # Looked up through the module, so tests can replace the resolver and never touch the network.
    result = verification.check_dns_txt(domain.domain, domain.verification_token)
    if result.verified:
        holder = session.scalar(
            select(Domain.id).where(
                Domain.domain == domain.domain,
                Domain.verification_status == "verified",
                Domain.id != domain.id,
            )
        )
        if holder is not None:
            raise ApiError(
                409, "domain_already_verified",
                f"Another account has already verified {domain.domain}. If you own it, contact support.",
            )
        domain.verification_status = "verified"
        domain.verified_at = utcnow()
        try:
            session.flush()  # the partial unique index is the final arbiter of "first to verify wins"
        except IntegrityError:
            session.rollback()
            raise ApiError(
                409, "domain_already_verified", f"Another account has already verified {domain.domain}."
            ) from None
    return VerifyResult(
        verified=result.verified, reason=result.reason, detail=result.detail, domain=_out(domain)
    )


# --- platform verification (Vercel, Netlify, Cloudflare Pages) ------------------------------------------

def _verify_with_platform(
    session: Session, user: User, payload_conn: str, project_id: str, hostname: str, domain_id: str | None
) -> DomainOut:
    from api.providers import cipher_or_error, list_limiter, to_api_error
    from core.provider_service import ProviderServiceError

    try:
        list_limiter.check(user.id)
    except Throttled as exc:
        raise ApiError(
            429, "too_many_attempts", f"Too many attempts. Try again in {exc.retry_after} seconds.",
            headers={"Retry-After": str(exc.retry_after)},
        ) from None
    list_limiter.record_failure(user.id)
    try:
        domain = provider_service.verify_platform_target(
            session, user, cipher_or_error(),
            connection_id=payload_conn, project_id=project_id, hostname=hostname, domain_id=domain_id,
        )
    except ProviderServiceError as exc:
        raise to_api_error(exc) from None
    return _out(domain)


@router.post("/provider", response_model=DomainOut)
def add_platform_target(
    payload: ProviderTargetRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> DomainOut:
    """Add a deployment as a verified target in one step: `Add & verify`.

    Ownership is decided by the platform, not by this request: `connection_id` must be the caller's own,
    `project_id` is fetched with that connection's token, and `hostname` must be one the platform lists
    on that project. All three come from the browser and none is trusted.
    """
    return _verify_with_platform(
        session, user, payload.connection_id, payload.project_id, payload.hostname, None
    )


@router.post("/{domain_id}/verify/provider", response_model=DomainOut)
def verify_platform_domain(
    domain_id: str,
    payload: ProviderVerifyRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> DomainOut:
    """Verify an existing pending or failed target through a connected platform account."""
    domain = _owned(session, user, domain_id)
    return _verify_with_platform(
        session, user, payload.connection_id, payload.project_id, domain.domain, domain.id
    )
