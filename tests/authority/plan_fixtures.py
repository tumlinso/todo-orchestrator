"""Small helpers for accepted-plan authority fixtures."""

from todo_orchestrator.contracts import StableId
from todo_orchestrator.planning.service import PlanService


def commit_plan(authority, auth, bearer_token, package_json, *, key="fixture-plan"):
    """Commit and return a real accepted plan through the public service path."""
    service = PlanService(auth)
    preview = service.preview(authority, package_json)
    result = service.commit(
        authority,
        bearer_token,
        package_json,
        reviewed_digest=preview.digest,
        idempotency_key=StableId(key),
        expected_authority_revision=preview.expected_authority_revision,
        expected_plan_revision_id=preview.expected_revision_id,
    )
    return service, result, service.load_accepted_plan(authority)
