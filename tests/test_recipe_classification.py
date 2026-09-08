"""Reported cake regression with controlled model output, not a model benchmark."""
import asyncio
import json
import logging

import pytest
from chat_system import local_llm
from chat_system.dlp import RuleDLPChecker
from chat_system.security_contracts import MessageSecurityContext, SecurityDecision, recipe_action_for_score
from chat_system.security_policy import SecurityPolicy
from test_security_integration import secured_server, account, quiet

CAKE = """a recipe for a chocolate cake!
flour
water
chocolate
cocoa powder
oil
yeast
mix all the dry ingredients, and then add water and oil"""
PIZZA = 'Mix 200 g flour with water and yeast; stretch into a round, top with tomatoes and mozzarella, then bake at 250 C.'


class NoURLs:
    def extract(self, text):
        return []

    def check(self, url):
        raise AssertionError('No external provider calls')


def model_reply(action, score):
    return json.dumps({'done': True, 'response': json.dumps({'action': action, 'risk_score': score})}).encode()


@pytest.fixture
def model(monkeypatch):
    for name in ('LOCAL_LLM_MODEL', 'LOCAL_LLM_ENDPOINT', 'LOCAL_LLM_TIMEOUT_SECONDS'):
        monkeypatch.delenv(name, raising=False)
    calls = []
    def fake(endpoint, payload, timeout):
        calls.append(payload)
        return model_reply('block', 10)  # Exact contradictory real-world response.
    monkeypatch.setattr(local_llm, '_call_model', fake)
    return calls


@pytest.mark.parametrize('prior', [None, 'hello', 'pineapple'])
def test_exact_cake_is_reviewed_and_allowed_even_after_blocked_attempt(model, prior, caplog):
    caplog.set_level(logging.INFO, logger='chat.security')
    checker = RuleDLPChecker()
    score, counts = checker._soft_score(CAKE)
    assert score == 70 and counts['anchors'] == 0 and counts['ingredients'] == 4
    policy = SecurityPolicy(checker, local_llm.OllamaRecipeClassifier(), NoURLs(), NoURLs())
    context = MessageSecurityContext(1, 1)
    if prior:
        previous = policy.evaluate(prior, context)
        assert previous.action == ('block' if prior == 'pineapple' else 'allow')
        assert not model
    result = policy.evaluate(CAKE, context)
    assert result.action == 'allow' and result.reason_code == 'security_allowed'
    assert result.risk_score == 70  # Aggregate rule metadata is not the recipe verdict.
    assert len(model) == 1
    assert json.loads(model[0]['prompt']) == {'text': CAKE, 'recent_attempts': [prior] if prior else []}
    assert 'action=allow risk_score=10 failure=inconsistent_action_score' in caplog.text
    assert CAKE not in caplog.text


@pytest.mark.parametrize('action,score', [('block', 0), ('block', 10), ('block', 29), ('allow', 30), ('allow', 99)])
def test_contradictions_resolve_by_score_in_adapter_and_injected_policy(monkeypatch, action, score, caplog):
    caplog.set_level(logging.INFO, logger='chat.security')
    monkeypatch.setattr(local_llm, '_call_model', lambda *args: model_reply(action, score))
    expected = recipe_action_for_score(score)
    assert local_llm.OllamaRecipeClassifier().classify(CAKE, []).action == expected
    class Contradictory:
        def classify(self, text, previous):
            return SecurityDecision(action, 'recipe_context_detected', score, 'local_llm')
    result = SecurityPolicy(RuleDLPChecker(), Contradictory(), NoURLs(), NoURLs()).evaluate(CAKE, MessageSecurityContext(1, 1))
    assert result.action == expected
    assert 'failure=inconsistent_action_score' in caplog.text


def test_prompt_examples_and_complete_or_split_recipe_without_keyword(monkeypatch):
    calls = []
    def fake(endpoint, payload, timeout):
        calls.append(json.loads(payload['prompt']))
        prompt = payload['system']
        for phrase in ('chocolate cake', 'No pizza keyword is required', 'recipe exists',
                       'current message', '0-29 means allow', '30-99 means block', 'score 85', 'score 90'):
            # Existing wording describes mentioning that a recipe exists.
            assert phrase in prompt
        return model_reply('block', 85)
    monkeypatch.setattr(local_llm, '_call_model', fake)
    policy = SecurityPolicy(RuleDLPChecker(), local_llm.OllamaRecipeClassifier(), NoURLs(), NoURLs())
    assert 'pizza' not in PIZZA.lower()
    assert RuleDLPChecker()._soft_score(PIZZA)[1]['anchors'] == 0
    assert policy.evaluate(PIZZA, MessageSecurityContext(1, 1)).reason_code == 'recipe_blocked'
    context = MessageSecurityContext(2, 1)
    for fragment in ('flour water yeast salt', '200 g', 'stretch into a round, top with tomatoes and mozzarella, then bake at 250 C'):
        result = policy.evaluate(fragment, context)
    assert result.reason_code == 'recipe_blocked'
    assert calls[-1]['recent_attempts'] == ['flour water yeast salt', '200 g']


@pytest.mark.parametrize('text', ['hey', 'I enjoy pizza with friends', 'I have a secret pizza recipe',
                                'I like chocolate cake recipes', CAKE])
def test_unrelated_current_text_after_recipe_context_can_be_allowed(monkeypatch, text):
    monkeypatch.setattr(local_llm, '_call_model', lambda *args: model_reply('allow', 5))
    policy = SecurityPolicy(RuleDLPChecker(), local_llm.OllamaRecipeClassifier(), NoURLs(), NoURLs())
    result = policy.evaluate(text, MessageSecurityContext(1, 1, (PIZZA,)))
    assert result.action == 'allow'


@pytest.mark.parametrize('failure', [TimeoutError(), ConnectionRefusedError(), RuntimeError(), b'bad JSON'])
def test_service_and_malformed_failures_still_close(monkeypatch, failure):
    def fake(*args):
        if isinstance(failure, Exception):
            raise failure
        return failure
    monkeypatch.setattr(local_llm, '_call_model', fake)
    result = SecurityPolicy(RuleDLPChecker(), local_llm.OllamaRecipeClassifier(), NoURLs(), NoURLs()).evaluate(CAKE, MessageSecurityContext(1, 1))
    assert result.action == 'block' and result.reason_code == 'security_check_unavailable'


def test_reported_cake_is_saved_and_delivered_but_recipe_is_not(secured_server, monkeypatch):
    monkeypatch.setattr(local_llm, '_call_model', lambda endpoint, payload, timeout:
        model_reply('block', 10 if json.loads(payload['prompt'])['text'] == CAKE else 85))
    async def run():
        a, b = await account(secured_server.uri, 'alice'), await account(secured_server.uri, 'bobby')
        try:
            await a.request('create_group', room_name='General')
            await b.request('join_group', room_name='General')
            assert (await a.request('send_message', room_name='General', content=CAKE))['ok']
            for client in (a, b):
                assert (await asyncio.wait_for(client.events.get(), 2))['content'] == CAKE
            assert (await a.request('send_message', room_name='General', content=PIZZA))['error'] == 'recipe_blocked'
            await quiet(a); await quiet(b)
            history = await a.request('history', room_name='General')
            assert [m['content'] for m in history['messages']] == [CAKE]
        finally:
            await a.close(); await b.close()
    asyncio.run(run())
