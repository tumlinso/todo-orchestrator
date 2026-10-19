"""Public next-work selection preserves plan/dispatch authorization boundaries."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from tests.api.test_standalone_independent import OWNER_CREDENTIAL, _plan
from tests.api.test_host_auth import FixtureAuthenticator
from todo_orchestrator.api import (
    CAPABILITY_DELEGATE_ACTION, DEFAULT_OWNER_ACTIONS, ProviderComposition, TodoApplication,
)
from todo_orchestrator.authority.auth import CapabilityDeniedError
from todo_orchestrator.contracts import EntityKind, StableId
from todo_orchestrator.coordination.service import RUN_DISPATCH_ACTION, RUN_SCHEDULE_ACTION
from todo_orchestrator.model import RunSchedule


class SelectionHost:
    def qualify_workspace(self, *_args):
        raise AssertionError("selection must not qualify a workspace")

    def inspect_attempt(self, *_args):
        raise AssertionError("selection must not inspect an attempt")


class SelectNextWorkPublicApiTests(unittest.TestCase):
    def test_run_task_and_default_selectors_need_dispatch_not_schedule_authority(self):
        with tempfile.TemporaryDirectory(prefix="todo-select-next-work-") as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            now = [datetime(2026, 10, 19, tzinfo=timezone.utc)]
            providers = ProviderComposition(
                attempt_host=SelectionHost(),
                principal_authenticator=FixtureAuthenticator(),
                clock=lambda: now[0],
            )
            actions = tuple(sorted({*DEFAULT_OWNER_ACTIONS, CAPABILITY_DELEGATE_ACTION}))
            with TodoApplication.initialize(
                root,
                project_id=StableId("select-next-work-project"),
                repository_id=StableId("select-next-work-repository"),
                authority_id=StableId("select-next-work-authority"),
                owner_credential=OWNER_CREDENTIAL,
                providers=providers,
                owner_actions=actions,
            ) as owner:
                package = _plan(owner.project, items=("alpha", "beta"))
                preview = owner.preview_plan(package)
                committed = owner.commit_plan(
                    package, preview, idempotency_key=StableId("select-next-work-plan"),
                )
                plan_revision_id = StableId(committed.result["plan_revision_id"])
                run_id = StableId("select-next-work-run")
                schedule = RunSchedule(
                    run_id, owner.ref(EntityKind.PLAN_REVISION, plan_revision_id),
                )
                owner.open_run(
                    plan_revision_id, schedule,
                    idempotency_key=StableId("select-next-work-open-run"),
                )
                issued = owner.delegate_principal(
                    "authenticated-user",
                    scope=owner.project.ref,
                    actions=(StableId("todo.attempt.claim"), RUN_DISPATCH_ACTION),
                    expires_at=now[0] + timedelta(hours=1),
                    idempotency_key=StableId("select-next-work-coder-grant"),
                )
                self.assertNotIn(RUN_SCHEDULE_ACTION, issued.capability.actions)
                before = owner.read_snapshot().authority_revision

                with TodoApplication.open(
                    root, bearer_token=issued.bearer_token, providers=providers,
                ) as coder:
                    run_selection = coder.select_next_work(run_id=run_id)
                    # The default serial lane makes alpha the only currently
                    # eligible target; selecting beta here should correctly
                    # respect the persisted queue order rather than bypass it.
                    task_selection = coder.select_next_work(run_id=run_id, target="alpha")
                    default_selection = coder.select_next_work()
                    with self.assertRaises(CapabilityDeniedError):
                        coder.read_run(run_id)

                self.assertEqual(run_selection.run.entity_id, run_id)
                self.assertEqual(task_selection.target.entity_id, StableId("alpha"))
                self.assertEqual(default_selection.run.entity_id, run_id)
                self.assertTrue(run_selection.workspace_qualification_required)
                self.assertEqual(owner.read_snapshot().authority_revision, before)


if __name__ == "__main__":
    unittest.main()
