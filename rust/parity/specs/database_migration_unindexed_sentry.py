"""Parity spec for PiDatabaseMigrationUnindexedSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDatabaseMigrationUnindexedSentry"

_mod = load_py_agent("pi_database_migration_unindexed_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDatabaseMigrationUnindexedSentry()
    out = agent.audit_migration_indexes(_mod.DatabaseMigrationUnindexedInput(**data))
    return out.model_dump()


# Clean/passing: foreign key column present, but an explicit index exists in the
# body -> the "index" keyword suppresses ALL findings.
_INDEXED = "\n".join(
    [
        "add_column :posts, :user_id, :integer",
        "add_index :posts, :user_id",
    ]
)

# Unindexed *_id column -> matched by the `\b[a-zA-Z0-9_]+_id\b` regex.
_UNINDEXED_ID = "user_id INT NOT NULL"

# `references` keyword (no index anywhere).
_REFERENCES = "t.references :customers"

# `foreign_key` keyword (no index anywhere).
_FOREIGN_KEY = "add_foreign_key :orders, :users"

# Multi-line: a mix of clean lines and several flaggable lines, no index keyword.
_MULTI = "\n".join(
    [
        "create_table :orders do |t|",
        "  t.integer :customer_id",
        "  t.references :products",
        "  t.string :name",
        "  add_foreign_key :orders, :users",
        "end",
    ]
)

# `unique_key` present -> suppresses findings even though there are *_id columns.
_UNIQUE_KEY = "\n".join(
    [
        "user_id INT",
        "ADD CONSTRAINT unique_key_user UNIQUE (user_id)",
    ]
)

# Uppercase keyword exercises the .lower() handling (CREATE INDEX -> "index").
_CREATE_INDEX = "\n".join(
    [
        "ALTER TABLE orders ADD COLUMN account_id INT;",
        "CREATE INDEX idx_account ON orders(account_id);",
    ]
)

SAMPLES = [
    {"input": {"file_path": "m.rb", "migration_code": _INDEXED}},
    {"input": {"file_path": "m.rb", "migration_code": _UNINDEXED_ID}},
    {"input": {"file_path": "m.rb", "migration_code": _REFERENCES}},
    {"input": {"file_path": "m.rb", "migration_code": _FOREIGN_KEY}},
    {"input": {"file_path": "m.rb", "migration_code": _MULTI}},
    {"input": {"file_path": "m.rb", "migration_code": _UNIQUE_KEY}},
    {"input": {"file_path": "m.sql", "migration_code": _CREATE_INDEX}},
    {"input": {"file_path": "m.rb", "migration_code": ""}},
    {"input": {"file_path": "m.rb", "migration_code": _UNINDEXED_ID, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "m.rb", "migration_code": _MULTI},
     "env": {"PI_DATABASE_MIGRATION_UNINDEXED_STRICT_MODE": "false"}},
    {"input": {"file_path": "m.rb", "migration_code": _MULTI},
     "env": {"PI_DATABASE_MIGRATION_UNINDEXED_STRICT_MODE": "true"}},
]
