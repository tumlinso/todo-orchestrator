"""Project-local transactional authority storage."""

from .sqlite import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    AuthorityAlreadyExistsError,
    AuthorityError,
    AuthorityIdentityMismatchError,
    AuthorityNotFoundError,
    AuthorityPublicationDurabilityUncertainError,
    InvalidAuthorityError,
    MigrationResult,
    ReadOnlyAuthorityError,
    SQLiteAuthority,
    UnsupportedAuthorityPlatformError,
    UnsupportedSchemaVersionError,
)

__all__ = [
    "APPLICATION_ID",
    "SCHEMA_VERSION",
    "AuthorityAlreadyExistsError",
    "AuthorityError",
    "AuthorityIdentityMismatchError",
    "AuthorityNotFoundError",
    "AuthorityPublicationDurabilityUncertainError",
    "InvalidAuthorityError",
    "MigrationResult",
    "ReadOnlyAuthorityError",
    "SQLiteAuthority",
    "UnsupportedAuthorityPlatformError",
    "UnsupportedSchemaVersionError",
]
