from pathlib import Path


ROOT = Path(__file__).parent


def test_graphql_values_use_variables_and_names_are_validated():
    source = (ROOT / "brinqa_connector.py").read_text()

    assert "GRAPHQL_NAME_PATTERN.fullmatch(data_model)" in source
    assert "GRAPHQL_NAME_PATTERN.fullmatch(value)" in source
    assert '\"variables\": {\"filter\": str(param[\"filter\"])}' in source
    assert '\"variables\": {\"typeName\": data_model.capitalize()}' in source
    assert 'filter: \"{filter_string}\"' not in source
