import json
from cortex.janitor.suggestions import review_lifecycle
from cortex.llm.base import LLMResult


class Provider:
    def __init__(self, text='{}'):
        self.text, self.calls = text, 0
    def complete(self, **kwargs):
        self.calls += 1
        return LLMResult(self.text, 'test')


def test_empty_input_does_not_spend():
    provider = Provider()
    assert review_lifecycle(provider, {}).suggestions == ()
    assert provider.calls == 0


def test_prompt_envelope_is_included_in_byte_budget():
    provider = Provider()
    assert review_lifecycle(provider, {'a':'b'}, max_bytes=24).error
    assert provider.calls == 0


def test_duplicate_suggestions_rejected():
    item = {'path':'a','state':'draft','reason':'review'}
    provider = Provider(json.dumps({'suggestions':[item,item]}))
    result = review_lifecycle(provider, {'a':'draft','b':'draft'})
    assert result.error and not result.suggestions
