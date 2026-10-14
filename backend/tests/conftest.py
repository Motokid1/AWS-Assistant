import pytest
@pytest.fixture(autouse=True)
def isolated_demo(monkeypatch):
    from src import demo
    demo.reset()
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED','true')
    monkeypatch.setenv('AWS_DEFAULT_REGION','us-east-1')
    yield
    demo.reset()
