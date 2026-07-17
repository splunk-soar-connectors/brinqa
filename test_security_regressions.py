import json
from pathlib import Path


ROOT = Path(__file__).parent


def test_graphql_values_use_variables_and_names_are_validated():
    source = (ROOT / "brinqa_connector.py").read_text()

    assert "GRAPHQL_NAME_PATTERN.fullmatch(data_model)" in source
    assert "GRAPHQL_NAME_PATTERN.fullmatch(value)" in source
    assert '\"variables\": {\"filter\": str(param[\"filter\"])}' in source
    assert '\"variables\": {\"typeName\": data_model.capitalize()}' in source
    assert 'filter: \"{filter_string}\"' not in source


def test_tls_verification_defaults_to_enabled():
    source = (ROOT / "brinqa_connector.py").read_text()
    manifest = json.loads((ROOT / "brinqa.json").read_text())

    assert manifest["configuration"]["verify_server_cert"]["default"] is True
    assert 'config.get("verify_server_cert", True)' in source
    assert 'config.get("verify_server_cert", False)' not in source
