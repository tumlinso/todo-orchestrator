"""Explicit provider composition for the standalone application facade."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from todo_orchestrator.contracts import ProviderIdentity
from todo_orchestrator.contracts.providers import (
    AttemptCredentialProvider,
    CommandExecutionProvider,
    ResourcePermitProvider,
)
from todo_orchestrator.authority.auth import PrincipalAuthenticator
from todo_orchestrator.providers.git import GitRepositoryConfig, GitRepositoryProvider


class ProviderUnavailableError(RuntimeError):
    """An operation needs a trusted host/provider that was not configured."""

    def __init__(self, port: str) -> None:
        self.port = port
        super().__init__(f"required trusted provider port is unavailable: {port}")


@dataclass(frozen=True)
class ProviderComposition:
    """Trusted ports injected by the application operator.

    Empty composition is suitable for plan, metadata, and authority read
    workflows. It deliberately supplies no pretend host observations.
    """

    attempt_host: object | None = None
    attempt_credential_provider: AttemptCredentialProvider | None = None
    host_identity: ProviderIdentity | None = None
    source_observer: object | None = None
    source_identity: ProviderIdentity | None = None
    verification_provider: object | None = None
    verification_identity: ProviderIdentity | None = None
    command_execution_provider: CommandExecutionProvider | None = None
    command_execution_identity: ProviderIdentity | None = None
    resource_permit_provider: ResourcePermitProvider | None = None
    resource_permit_identity: ProviderIdentity | None = None
    declaration_observer: object | None = None
    declaration_identity: ProviderIdentity | None = None
    git_provider: GitRepositoryProvider | None = None
    clock: Callable[[], datetime] | None = None
    principal_authenticator: PrincipalAuthenticator | None = None

    def __post_init__(self) -> None:
        if self.clock is not None and not callable(self.clock):
            raise TypeError("clock must be callable or None")
        if self.principal_authenticator is not None:
            if not callable(getattr(self.principal_authenticator, "authenticate", None)):
                raise TypeError("principal_authenticator must implement authenticate")
            provider_id = getattr(self.principal_authenticator, "provider_id", None)
            if (not isinstance(provider_id, str) or not provider_id
                    or provider_id != provider_id.strip()):
                raise ValueError("principal_authenticator.provider_id must be non-empty trimmed text")
        for identity, name in (
            (self.host_identity, "host_identity"), (self.source_identity, "source_identity"),
            (self.verification_identity, "verification_identity"),
            (self.declaration_identity, "declaration_identity"),
        ):
            if identity is not None and not isinstance(identity, ProviderIdentity):
                raise TypeError(f"{name} must be ProviderIdentity or None")
        if self.attempt_host is not None and not all(
            callable(getattr(self.attempt_host, method, None))
            for method in ("qualify_workspace", "inspect_attempt")
        ):
            raise TypeError("attempt_host must implement qualify_workspace and inspect_attempt")
        if self.attempt_credential_provider is not None and not callable(
            getattr(self.attempt_credential_provider, "prepare_attempt_credential", None)
        ):
            raise TypeError("attempt_credential_provider must implement prepare_attempt_credential")
        if self.source_observer is not None and not callable(getattr(self.source_observer, "observe", None)):
            raise TypeError("source_observer must implement observe")
        if self.verification_provider is not None and not all(
            callable(getattr(self.verification_provider, method, None)) for method in ("verify", "inspect")
        ):
            raise TypeError("verification_provider must implement verify and inspect")
        if self.command_execution_provider is not None and not all(
            callable(getattr(self.command_execution_provider, method, None))
            for method in ("execute", "inspect")
        ):
            raise TypeError("command_execution_provider must implement execute and inspect")
        if (self.command_execution_provider is None) != (self.command_execution_identity is None):
            raise ValueError("command execution provider and identity must be supplied together")
        if self.command_execution_identity is not None and not isinstance(
            self.command_execution_identity, ProviderIdentity
        ):
            raise TypeError("command_execution_identity must be a ProviderIdentity")
        if self.resource_permit_provider is not None and not all(
            callable(getattr(self.resource_permit_provider, method, None))
            for method in ("reserve", "release", "inspect")
        ):
            raise TypeError("resource_permit_provider must implement reserve, release, and inspect")
        if (self.resource_permit_provider is None) != (self.resource_permit_identity is None):
            raise ValueError("resource permit provider and identity must be supplied together")
        if self.resource_permit_identity is not None and not isinstance(
            self.resource_permit_identity, ProviderIdentity
        ):
            raise TypeError("resource_permit_identity must be a ProviderIdentity")
        if self.declaration_observer is not None and not callable(
            getattr(self.declaration_observer, "observe_declaration", None)
        ):
            raise TypeError("declaration_observer must implement observe_declaration")
        if self.git_provider is not None and not isinstance(self.git_provider, GitRepositoryProvider):
            raise TypeError("git_provider must be a GitRepositoryProvider or None")
        if self.git_provider is not None:
            identity = self.git_provider.identity
            if self.attempt_host is not self.git_provider or self.host_identity != identity:
                raise ValueError("Git provider must be the configured host and matching host identity")
            if self.source_observer is not self.git_provider or self.source_identity != identity:
                raise ValueError("Git provider must be the configured source observer and matching identity")

    @classmethod
    def local_git(
        cls,
        config: GitRepositoryConfig,
        *,
        process_observer: object | None = None,
        child_observer: object | None = None,
        verification_provider: object | None = None,
        verification_identity: ProviderIdentity | None = None,
        command_execution_provider: CommandExecutionProvider | None = None,
        command_execution_identity: ProviderIdentity | None = None,
        resource_permit_provider: ResourcePermitProvider | None = None,
        resource_permit_identity: ProviderIdentity | None = None,
        declaration_observer: object | None = None,
        declaration_identity: ProviderIdentity | None = None,
        principal_authenticator: PrincipalAuthenticator | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> "ProviderComposition":
        """Explicitly configure the native local Git provider.

        A missing process observer remains unknown; this helper never invents
        process-stop evidence. Repository paths and refs must be selected by
        the caller in a trusted `GitRepositoryConfig`.
        """
        provider = GitRepositoryProvider(
            config, clock=clock, process_observer=process_observer,
            child_observer=child_observer,
        )
        return cls(
            attempt_host=provider,
            host_identity=provider.identity,
            source_observer=provider,
            source_identity=provider.identity,
            verification_provider=verification_provider,
            verification_identity=verification_identity,
            command_execution_provider=command_execution_provider,
            command_execution_identity=command_execution_identity,
            resource_permit_provider=resource_permit_provider,
            resource_permit_identity=resource_permit_identity,
            declaration_observer=declaration_observer,
            declaration_identity=declaration_identity,
            git_provider=provider,
            principal_authenticator=principal_authenticator,
            clock=clock,
        )


__all__ = ["ProviderComposition", "ProviderUnavailableError"]
