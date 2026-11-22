"""Locked feature-list tests (Prompt B test list: feature list)."""
from src import config


def test_feature_count_is_20():
    assert len(config.FEATURES) == 20
    assert len(set(config.FEATURES)) == 20


def test_no_overlap_with_forbidden_columns():
    forbidden = set(
        config.ORACLE_FEATURES
        + config.RULE_FEATURES
        + config.META_COLUMNS
        + config.REFGRAPH_EDGE_COLUMNS
        + [config.LABEL_COL]
    )
    assert not set(config.FEATURES) & forbidden
    assert forbidden == set(config.FORBIDDEN_MODEL_INPUTS)


def test_locked_lists_exact():
    assert config.ORACLE_FEATURES == ["file_age_minutes", "created_in_window"]
    assert config.RULE_FEATURES == ["rule_hit_count"]
    assert config.V1_META_COLUMNS == ["run_id", "technique_id", "variant", "launcher", "artifact_key"]
    assert len(config.V2_PROVENANCE_COLUMNS) == 15
    assert "pair_group_id" in config.V2_PROVENANCE_COLUMNS
    assert config.META_COLUMNS == config.V1_META_COLUMNS + config.V2_PROVENANCE_COLUMNS
    assert config.REFGRAPH_EDGE_COLUMNS == ["ref_targets", "ref_type", "linked_artifact_keys"]
    assert config.RULE_EXPORT_COLUMNS == [
        "task_name",
        "service_name",
        "start_mode",
        "task_triggers",
        "account_is_admin",
        "account_enabled",
    ]
    assert config.LABEL_COL == "label"


def test_every_categorical_has_na_level():
    for feat in config.CATEGORICAL_FEATURES:
        assert "na" in config.CATEGORICAL_LEVELS[feat], feat


def test_feature_groups_only_reference_features():
    for group, feats in config.FEATURE_GROUPS.items():
        assert set(feats) <= set(config.FEATURES), group


def test_seed_is_42():
    assert config.SEED == 42


def test_lolbin_list_fixed():
    assert config.LOLBIN_LIST == [
        "certutil", "mshta", "regsvr32", "rundll32", "wmic", "bitsadmin", "cscript", "wscript",
        "msbuild", "installutil", "forfiles", "schtasks", "sc", "reg",
    ]
