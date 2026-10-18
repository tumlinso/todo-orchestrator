"""Pure attenuation and conflict checks for subordinate execution scopes."""

from __future__ import annotations

from todo_orchestrator.model.eligibility import AttemptScopeSnapshot


def _overlaps(first: str, second: str) -> bool:
    """Return whether two normalized repository paths overlap by ancestry."""
    return first == second or first.startswith(second + "/") or second.startswith(first + "/")


def _contains(parent: str, child: str) -> bool:
    return child == parent or child.startswith(parent + "/")


def require_child_scope_subset(
    parent: AttemptScopeSnapshot,
    child: AttemptScopeSnapshot,
) -> None:
    """Require child paths and locks to be a strict, safe subset of a parent.

    Parent paths are repository-relative and validated by
    :class:`AttemptScopeSnapshot`. ``forbidden`` entries are deny rules: any
    overlap rejects a child path. A writable parent path permits child reads or
    writes, while a readable parent path permits only child reads. A narrower
    child access mode counts as attenuation even when the path is unchanged.
    """
    if not isinstance(parent, AttemptScopeSnapshot) or not isinstance(child, AttemptScopeSnapshot):
        raise TypeError("parent and child must be AttemptScopeSnapshot values")

    parent_paths = tuple(parent.paths)
    child_paths = tuple(child.paths)
    if len({path for path, _access in parent_paths}) != len(parent_paths):
        raise ValueError("parent scope cannot repeat a path")
    if len({name for name, _mode in parent.locks}) != len(parent.locks):
        raise ValueError("parent scope cannot repeat a lock")
    if len({path for path, _access in child_paths}) != len(child_paths):
        raise ValueError("child scope cannot repeat a path")
    if len({name for name, _mode in child.locks}) != len(child.locks):
        raise ValueError("child scope cannot repeat a lock")
    if any(access not in {"read", "write"} for _path, access in child_paths):
        raise ValueError("child paths must request read or write access")
    if not child_paths:
        raise ValueError("child scope must include at least one read or write path")

    for child_path, child_access in child_paths:
        for parent_path, parent_access in parent_paths:
            if _overlaps(parent_path, child_path) and parent_access == "forbidden":
                raise ValueError(f"child path overlaps a forbidden parent path: {child_path}")

        # Path grants are additive: a broad read descriptor does not cancel a
        # narrower write grant. The child path must be covered by an ancestor
        # grant that supplies the requested access.
        required_parent_access = "write" if child_access == "write" else None
        covered = any(
            _contains(parent_path, child_path)
            and parent_access in ({"write"} if required_parent_access else {"read", "write"})
            for parent_path, parent_access in parent_paths
        )
        if not covered:
            raise ValueError(f"child path is outside parent access scope: {child_path}")

    parent_locks = dict(parent.locks)
    for name, mode in child.locks:
        parent_mode = parent_locks.get(name)
        if parent_mode is None:
            raise ValueError(f"child lock is not present in parent scope: {name}")
        if mode == "exclusive" and parent_mode != "exclusive":
            raise ValueError(f"child exclusive lock exceeds parent lock authority: {name}")

    # Every parent grant must be represented by an equally broad or stronger
    # child grant before the scopes count as equivalent. This avoids treating
    # redundant descendant descriptors as meaningful attenuation.
    parent_rights_retained = True
    for parent_path, parent_access in parent_paths:
        if parent_access == "forbidden":
            continue
        required_child_access = "write" if parent_access == "write" else None
        represented = any(
            _contains(child_path, parent_path)
            and child_access in ({"write"} if required_child_access else {"read", "write"})
            for child_path, child_access in child_paths
        )
        if not represented:
            parent_rights_retained = False
            break

    locks_equal = frozenset(child.locks) == frozenset(parent.locks)
    if parent_rights_retained and locks_equal:
        raise ValueError("child scope must be strictly narrower than parent scope")


def child_scopes_conflict(first: AttemptScopeSnapshot, second: AttemptScopeSnapshot) -> bool:
    """Return whether two child scopes have overlapping exclusive resources."""
    if not isinstance(first, AttemptScopeSnapshot) or not isinstance(second, AttemptScopeSnapshot):
        raise TypeError("child scopes must be AttemptScopeSnapshot values")

    if any(
        _overlaps(first_path, second_path)
        and (first_access == "write" or second_access == "write")
        for first_path, first_access in first.paths
        for second_path, second_access in second.paths
    ):
        return True

    return any(
        first_name == second_name and (first_mode == "exclusive" or second_mode == "exclusive")
        for first_name, first_mode in first.locks
        for second_name, second_mode in second.locks
    )


__all__ = ["child_scopes_conflict", "require_child_scope_subset"]
