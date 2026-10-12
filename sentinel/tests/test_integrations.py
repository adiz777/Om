import pytest
from app.integrations import validate_domain

def test_validate_domain_normalizes_case_and_trailing_dot():
    assert validate_domain('Example.COM.') == 'example.com'

@pytest.mark.parametrize('value', ['', 'localhost', '127.0.0.1', 'example', 'https://example.com', '-bad.example.com', 'bad..example.com', 'example.local'])
def test_rejects_invalid_or_local_targets(value):
    with pytest.raises(ValueError):
        validate_domain(value)
