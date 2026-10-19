# Export and explicit restore

R04 was accepted at development authority revision 172 after required gate
revision 171 passed. The isolated source suite passed all 389 tests in
137.418 seconds; focused export discovery passed 11 tests. Independent review
covered sidecar preservation and structural credential collisions. Backup and
restore qualification used disposable authorities only.

`AuthorityExportService` exposes a versioned read model and a derived Markdown
view. `AuthorityReadModelV1` is a deterministic semantic projection of the
accepted plan and authority history, including authored titles, objectives,
requirements, and canonical declaration facts. It omits authentication
verifiers and token digests, message and finding bodies, and provider request
or receipt payloads. Authored domain text is retained; this projection is not
a universal free-text secret scanner, nor a replacement authority.

The SQLite backup is a separate, point-in-time artifact. `backup()` requires
the `todo.authority.backup` action, an expected semantic revision, and a new
destination path. It writes atomically without replacing an existing file and
returns a manifest binding the artifact digest, schema version, project and
authority identities, semantic revision, and logical fingerprint. The full
database includes authentication state such as password hashes and
capability-token digests; bearer tokens are not stored in plaintext.

Opening or reading an authority does not create, repair, migrate, or restore a
missing database. `restore_backup()` is a separate explicit operation. It
requires the manifest and caller-supplied expected project, authority, and
semantic revision. Before publishing to a missing destination, it verifies the
artifact digest, SQLite integrity and foreign keys, supported schema, exact
identity and revision, and logical fingerprint. It never overwrites an
existing destination.

Restoration reproduces the backup's authentication state at that point in
time. It cannot establish whether credentials were revoked later or whether
external source/evidence remains current. A restored authority is therefore
read-only when returned by the restore API; operators must separately decide
whether and how that historical copy should be opened for further work.
