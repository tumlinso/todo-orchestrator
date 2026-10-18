"""Focused pure tests for child path/access/lock attenuation."""

import unittest

from todo_orchestrator.coordination.child_scope import (
    child_scopes_conflict,
    require_child_scope_subset,
)
from todo_orchestrator.model.eligibility import AttemptScopeSnapshot


def scope(paths=(), locks=()):
    return AttemptScopeSnapshot(tuple(paths), tuple(locks))


class ChildScopeTests(unittest.TestCase):
    def test_child_can_take_a_strict_nested_path_and_bounded_locks(self):
        parent = scope(
            (("src/owned", "write"), ("docs/owned", "read")),
            (("workspace", "exclusive"), ("index", "shared")),
        )
        child = scope(
            (("src/owned/child", "write"), ("docs/owned/guide.md", "read")),
            (("workspace", "shared"),),
        )
        require_child_scope_subset(parent, child)

    def test_read_child_at_same_path_is_narrower_than_parent_write(self):
        require_child_scope_subset(
            scope((("src/owned", "write"),)),
            scope((("src/owned", "read"),)),
        )

    def test_exact_effective_scope_is_rejected_even_if_order_differs(self):
        parent = scope((("src/owned", "write"), ("docs/owned", "read")),
                       (("index", "shared"), ("workspace", "exclusive")))
        equal = scope((("docs/owned", "read"), ("src/owned", "write")),
                      (("workspace", "exclusive"), ("index", "shared")))
        with self.assertRaisesRegex(ValueError, "strictly narrower"):
            require_child_scope_subset(parent, equal)

    def test_outside_path_and_missing_parent_path_are_rejected(self):
        parent = scope((("src/owned", "write"),))
        with self.assertRaisesRegex(ValueError, "outside parent"):
            require_child_scope_subset(parent, scope((("src/other/file.py", "write"),)))
        with self.assertRaisesRegex(ValueError, "at least one"):
            require_child_scope_subset(parent, scope((), ()))

    def test_forbidden_parent_overlap_is_denied_in_both_directions(self):
        parent = scope((("src/owned", "write"), ("src/owned/private", "forbidden")))
        for child_path in ("src/owned/private", "src/owned"):
            with self.subTest(child_path=child_path):
                with self.assertRaisesRegex(ValueError, "forbidden parent"):
                    require_child_scope_subset(parent, scope(((child_path, "read"),)))

    def test_read_only_parent_cannot_delegate_write_and_child_cannot_request_forbidden(self):
        parent = scope((("src/owned", "read"),))
        with self.assertRaisesRegex(ValueError, "outside parent"):
            require_child_scope_subset(parent, scope((("src/owned/file.py", "write"),)))
        with self.assertRaisesRegex(ValueError, "read or write access"):
            require_child_scope_subset(parent, scope((("src/owned/file.py", "forbidden"),)))

    def test_additive_broad_read_does_not_cancel_narrow_write(self):
        parent = scope((("src", "read"), ("src/generated", "write")))
        require_child_scope_subset(
            parent,
            scope((("src/generated/output.py", "write"),)),
        )

    def test_redundant_parent_descriptors_do_not_make_equal_rights_narrower(self):
        parent = scope((("src", "write"), ("src/nested", "write")))
        with self.assertRaisesRegex(ValueError, "strictly narrower"):
            require_child_scope_subset(parent, scope((("src", "write"),)))

    def test_child_locks_must_be_inherited_and_not_widened(self):
        parent = scope((("src/owned", "write"),), (("shared-cache", "shared"),
                                                      ("checkout", "exclusive")))
        require_child_scope_subset(parent, scope((("src/owned/child", "write"),),
                                                  (("shared-cache", "shared"),)))
        with self.assertRaisesRegex(ValueError, "not present"):
            require_child_scope_subset(parent, scope((("src/owned/child", "write"),),
                                                      (("new-lock", "shared"),)))
        with self.assertRaisesRegex(ValueError, "exceeds parent"):
            require_child_scope_subset(parent, scope((("src/owned/child", "write"),),
                                                      (("shared-cache", "exclusive"),)))

    def test_duplicate_child_paths_or_locks_are_not_canonical_requests(self):
        parent = scope((("src/owned", "write"),), (("cache", "exclusive"),))
        with self.assertRaisesRegex(ValueError, "repeat a path"):
            require_child_scope_subset(
                parent, scope((("src/owned/a", "read"), ("src/owned/a", "write"))),
            )
        with self.assertRaisesRegex(ValueError, "repeat a lock"):
            require_child_scope_subset(
                parent, scope((("src/owned/a", "write"),), (("cache", "shared"), ("cache", "shared"))),
            )

    def test_scope_validation_rejects_non_repository_paths(self):
        for path in ("/absolute/path", "../escape", "src/../escape", "src\\escape"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    scope(((path, "read"),))

    def test_sibling_path_conflicts_follow_ancestry_and_write_access(self):
        parent = scope((("src/owned", "write"),))
        nested_write = scope((("src/owned/child", "write"),))
        nested_read = scope((("src/owned/child", "read"),))
        sibling_read = scope((("docs/owned", "read"),))
        self.assertTrue(child_scopes_conflict(parent, nested_read))
        self.assertTrue(child_scopes_conflict(nested_write, nested_read))
        self.assertFalse(child_scopes_conflict(nested_read, scope((("src/owned/child/file", "read"),))))
        self.assertFalse(child_scopes_conflict(nested_write, sibling_read))

    def test_sibling_lock_conflicts_only_when_either_side_is_exclusive(self):
        self.assertFalse(child_scopes_conflict(
            scope((("src/a", "read"),), (("cache", "shared"),)),
            scope((("src/b", "read"),), (("cache", "shared"),)),
        ))
        self.assertTrue(child_scopes_conflict(
            scope((("src/a", "read"),), (("cache", "exclusive"),)),
            scope((("src/b", "read"),), (("cache", "shared"),)),
        ))


if __name__ == "__main__":
    unittest.main()
