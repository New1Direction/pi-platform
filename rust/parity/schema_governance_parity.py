"""Parity harness for the deterministic cores of schema/evolution.py and
governance/compiler.py vs their Rust ports (pi_core.schema_op / governance_op).

Compares — byte-for-byte, including SHA-256 fingerprints/hashes:
  schema:     fingerprint, compatibility validate (diff + rule check),
              migration-path BFS, data migration
  governance: rule_hash, compiled_hash, fail-closed priority decision + decision_hash

Run:  PYTHONPATH=.:../../src python schema_governance_parity.py
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

import pi_core  # noqa: E402
from pi_event_fabric.schema.evolution import (  # noqa: E402
    ArtifactSchema, CompatibilityLevel, CompatibilityValidator, FieldSchema,
    MigrationStep, MigrationDAG,
)
from pi_event_fabric.governance.compiler import (  # noqa: E402
    Condition, ConditionOperator, Effect, GovernanceEngine, GovernanceRule,
    PolicyCompiler, PolicyValidationError,
)

mismatches = []


def cmp(label, a, b):
    if a != b:
        mismatches.append((label, a, b))


# ── schema helpers ──────────────────────────────────────────────────────────
def py_schema(spec):
    fields = tuple(
        FieldSchema(
            name=f["name"], type=f["type"], required=f.get("required", True),
            default=f.get("default"), description=f.get("description", ""),
        )
        for f in spec["fields"]
    )
    return ArtifactSchema(
        schema_name=spec["schema_name"], version=spec["version"], fields=fields,
        compatibility=CompatibilityLevel(spec["compatibility"]),
    )


def py_report_dict(r):
    return {
        "old_fingerprint": r.old_fingerprint, "new_fingerprint": r.new_fingerprint,
        "compatible": r.compatible, "level": r.level.value,
        "changes": [{**c, "type": c["type"].value} for c in r.changes],
        "violations": r.violations,
    }


SCHEMAS = [
    {"schema_name": "Artifact", "version": "1", "compatibility": "backward",
     "fields": [{"name": "id", "type": "str"}, {"name": "size", "type": "int"}]},
    {"schema_name": "Artifact", "version": "2", "compatibility": "backward",
     "fields": [{"name": "id", "type": "str"}, {"name": "size", "type": "int"},
                {"name": "tag", "type": "str", "required": False}]},
    {"schema_name": "Artifact", "version": "3", "compatibility": "backward",
     "fields": [{"name": "id", "type": "str"}, {"name": "size", "type": "int"},
                {"name": "mandatory", "type": "str", "required": True}]},
    {"schema_name": "Artifact", "version": "4", "compatibility": "forward",
     "fields": [{"name": "id", "type": "str"}]},
    {"schema_name": "Artifact", "version": "5", "compatibility": "full",
     "fields": [{"name": "id", "type": "int", "default": 0}, {"name": "uni", "type": "str", "description": "café ☃"}]},
]


def run_schema():
    for s in SCHEMAS:
        py_fp = py_schema(s).fingerprint.value
        rs_fp = json.loads(pi_core.schema_op("fingerprint", json.dumps({"schema": s})))
        cmp(f"schema.fingerprint[{s['version']}]", py_fp, rs_fp)

    for i in range(len(SCHEMAS)):
        for j in range(len(SCHEMAS)):
            old, new = SCHEMAS[i], SCHEMAS[j]
            py = py_report_dict(CompatibilityValidator.validate(py_schema(old), py_schema(new)))
            rs = json.loads(pi_core.schema_op("validate", json.dumps({"old": old, "new": new})))
            cmp(f"schema.validate[{old['version']}->{new['version']}]", py, rs)

    # migration path + data migration
    steps = [
        {"migration_id": "m1", "from_fingerprint": "fpA", "to_fingerprint": "fpB",
         "transformation_type": "add_field", "field_name": "tag", "parameters": {"default": "x"}},
        {"migration_id": "m2", "from_fingerprint": "fpB", "to_fingerprint": "fpC",
         "transformation_type": "rename_field", "field_name": "",
         "parameters": {"old_name": "tag", "new_name": "label"}},
        {"migration_id": "m3", "from_fingerprint": "fpA", "to_fingerprint": "fpZ",
         "transformation_type": "remove_field", "field_name": "size", "parameters": {}},
    ]
    dag = MigrationDAG()
    for s in steps:
        dag.register(MigrationStep(
            migration_id=s["migration_id"], from_fingerprint=s["from_fingerprint"],
            to_fingerprint=s["to_fingerprint"], direction="forward",
            transformation_type=s["transformation_type"], field_name=s["field_name"],
            parameters=s["parameters"],
        ))
    for frm, to in [("fpA", "fpC"), ("fpA", "fpZ"), ("fpA", "fpA"), ("fpB", "fpA"), ("fpA", "nope")]:
        py_path = [st.migration_id for st in dag.find_path(frm, to)]
        rs_path = json.loads(pi_core.schema_op("find_path", json.dumps({"steps": steps, "from": frm, "to": to})))
        cmp(f"schema.find_path[{frm}->{to}]", py_path, rs_path)

    # data migration along a path (apply each step)
    data = {"id": "x1", "size": 10, "tag": "hello"}
    reg = _PyRegistryShim(steps)
    for frm, to, direction in [("fpA", "fpC", "forward"), ("fpA", "fpZ", "forward")]:
        py_res = reg.migrate(dict(data), frm, to, direction)
        rs_res = json.loads(pi_core.schema_op("migrate_data", json.dumps(
            {"data": data, "steps": steps, "from": frm, "to": to, "direction": direction})))
        cmp(f"schema.migrate_data[{frm}->{to}]", py_res, rs_res)


class _PyRegistryShim:
    """Replays apply_migration along a path using the real Python logic."""
    def __init__(self, steps):
        self.dag = MigrationDAG()
        self.objs = {}
        for s in steps:
            st = MigrationStep(
                migration_id=s["migration_id"], from_fingerprint=s["from_fingerprint"],
                to_fingerprint=s["to_fingerprint"], direction="forward",
                transformation_type=s["transformation_type"], field_name=s["field_name"],
                parameters=s["parameters"])
            self.dag.register(st)
            self.objs[s["migration_id"]] = st

    def migrate(self, data, frm, to, direction):
        from pi_event_fabric.schema.evolution import SchemaRegistry
        # reuse SchemaRegistry.apply_migration logic without DB
        path = self.dag.find_path(frm, to)
        result = data
        for st in path:
            result = SchemaRegistry.apply_migration(self, result, st, direction)
        return result


# ── governance ──────────────────────────────────────────────────────────────
def py_evaluate(rules_spec, context):
    engine = GovernanceEngine()
    for rs in rules_spec:
        conds = tuple(
            Condition(field=c["field"], operator=ConditionOperator(c["operator"]), value=c["value"])
            for c in rs["conditions"]
        )
        rule = GovernanceRule(
            rule_id=rs["rule_id"], name=rs["name"], description=rs["description"],
            target_scope=rs["target_scope"], conditions=conds, effect=Effect(rs["effect"]),
            priority=rs["priority"], version=rs["version"], parent_rule_id=rs.get("parent_rule_id"),
        )
        engine.load_policy(PolicyCompiler.compile(rule))
    d = engine.evaluate(context)
    return {
        "decision_id": d.decision_id, "context_id": d.context_id, "effect": d.effect.value,
        "matched_rules": d.matched_rules, "denied_by": d.denied_by,
        "decision_hash": d.decision_hash, "evaluated_at": d.evaluated_at,
    }


def rule(rid, effect, prio, conds, ver="1"):
    return {"rule_id": rid, "name": rid, "description": "d", "target_scope": "global",
            "conditions": conds, "effect": effect, "priority": prio, "version": ver}


RULESETS = [
    [rule("allow_read", "allow", 5, [{"field": "action", "operator": "eq", "value": "read"}]),
     rule("deny_write", "deny", 1, [{"field": "action", "operator": "eq", "value": "write"}])],
    [rule("approval_prod", "require_approval", 2,
          [{"field": "stage", "operator": "in", "value": ["prod", "staging"]},
           {"field": "actor_id", "operator": "starts_with", "value": "svc-"}])],
    [rule("audit_all", "audit", 9, [{"field": "tenant_id", "operator": "exists", "value": None}]),
     rule("allow_small", "allow", 3, [{"field": "epoch_number", "operator": "lt", "value": 100}])],
]
CONTEXTS = [
    {"action": "read", "correlation_id": "c1", "timestamp": "2026-01-01T00:00:00Z"},
    {"action": "write", "correlation_id": "c2"},
    {"stage": "prod", "actor_id": "svc-x", "correlation_id": "c3"},
    {"stage": "prod", "actor_id": "human", "correlation_id": "c4"},
    {"tenant_id": "t1", "epoch_number": 50, "correlation_id": "c5"},
    {"epoch_number": 200, "correlation_id": "c6"},
    {"correlation_id": "c7"},
]


def run_governance():
    for ri, rules in enumerate(RULESETS):
        for r in rules:
            spec = {**r}
            py_rule = GovernanceRule(
                rule_id=r["rule_id"], name=r["name"], description=r["description"],
                target_scope=r["target_scope"],
                conditions=tuple(Condition(c["field"], ConditionOperator(c["operator"]), c["value"]) for c in r["conditions"]),
                effect=Effect(r["effect"]), priority=r["priority"], version=r["version"],
            )
            cmp(f"gov.rule_hash[{r['rule_id']}]", py_rule.rule_hash,
                json.loads(pi_core.governance_op("rule_hash", json.dumps({"rule": spec}))))
        for ci, ctx in enumerate(CONTEXTS):
            py = py_evaluate(rules, ctx)
            rs = json.loads(pi_core.governance_op("evaluate", json.dumps({"rules": rules, "context": ctx})))
            cmp(f"gov.evaluate[set{ri}/ctx{ci}]", py, rs)

    # validation-error parity (disallowed field + regex op)
    for bad in [[rule("r", "allow", 1, [{"field": "secret", "operator": "eq", "value": 1}])],
                [rule("r", "allow", 1, [{"field": "action", "operator": "matches", "value": ".*"}])]]:
        try:
            py_evaluate(bad, {})
            pe = None
        except PolicyValidationError:
            pe = "ERR"
        try:
            json.loads(pi_core.governance_op("evaluate", json.dumps({"rules": bad, "context": {}})))
            re_ = None
        except Exception:
            re_ = "ERR"
        cmp("gov.validation_error", pe, re_)


def main():
    run_schema()
    run_governance()
    if mismatches:
        print(f"SCHEMA/GOVERNANCE PARITY: {len(mismatches)} MISMATCH(es)\n")
        for label, a, b in mismatches[:12]:
            print(f"  [{label}]\n    python: {a}\n    rust:   {b}\n")
        sys.exit(1)
    print("SCHEMA/GOVERNANCE PARITY: ALL MATCH — fingerprints, compatibility, migrations, "
          "governance decisions (incl. SHA-256 hashes) byte-identical")


if __name__ == "__main__":
    main()
