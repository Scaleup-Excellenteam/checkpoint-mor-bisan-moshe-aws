"""Regression cases for the approved scoring and observability corrections."""
import json
import logging
import re
import time

import httpx
import pytest
from chat_system import local_llm, url_security
from chat_system.dlp import RuleDLPChecker
from chat_system.security_contracts import MessageSecurityContext, SecurityDecision
from chat_system.security_policy import SecurityPolicy


class Classifier:
    def __init__(self):
        self.calls = []

    def classify(self, text, previous):
        self.calls.append((text, previous))
        return SecurityDecision('allow', 'recipe_context_not_detected', 5, 'local_llm')


class URLs:
    def extract(self, text):
        return []

    def check(self, url):
        raise AssertionError('No external requests')


def test_reported_20_to_10_is_not_same_window_accumulation():
    checker, classifier = RuleDLPChecker(), Classifier()
    first, second = 'flour water yeast salt', 'pizza'
    assert checker.check('message', first).risk_score == 20
    assert checker.check('message', second).risk_score == 10
    policy = SecurityPolicy(checker, classifier, URLs(), URLs())
    context = MessageSecurityContext(1, 1)
    assert policy.evaluate(first, context).risk_score == 20
    assert policy.evaluate(second, context).risk_score == 30
    assert classifier.calls == [(second, (first,))]
    # Different scope or a fresh policy really can produce the apparent drop.
    assert policy.evaluate(second, MessageSecurityContext(2, 1)).risk_score == 10
    assert policy.evaluate(second, MessageSecurityContext(1, 2)).risk_score == 10
    assert SecurityPolicy(checker, classifier, URLs(), URLs()).evaluate(second, context).risk_score == 10


@pytest.mark.parametrize('text,score', [
    ('recipe recipes recpie recipie', 10), ('ingredient ingredients ingrediants', 5),
    ('tomato tomatoes tomatos t0mato', 5), ('cheese cheeese chese', 5),
    ('mix mixed mixing', 15), ('bake baking baked', 15),
    ('fl0ur', 5), ('mushrooms olives garlic onion', 20),
    ('mоzzarella', 5), ('tomatο', 5), ('mozzarela', 5),
    ('two cups', 20), ('half tsp', 20), ('3 oz', 20), ('2 pounds', 20),
    ('I have the ingredients for the secret pizza recipe', 35),
    ('floor waiter boil', 0), ('piazza', 0),
])
def test_soft_forms(text, score):
    result = RuleDLPChecker().check('message', text)
    assert result.risk_score == score
    assert result.action != 'block'


def test_ten_total_and_exact_expiry():
    clock = [0.0]
    policy = SecurityPolicy(RuleDLPChecker(), Classifier(), URLs(), URLs())
    policy._clock = lambda: clock[0]
    ctx = MessageSecurityContext(1, 1)
    assert policy.evaluate('pizza', ctx).risk_score == 10
    for _ in range(9):
        assert policy.evaluate('hey', ctx).risk_score == 10
    assert policy.evaluate('hey', ctx).risk_score == 0
    policy.evaluate('pizza', ctx)
    clock[0] = 299.999
    assert policy.evaluate('hey', ctx).risk_score == 10
    clock[0] = 300
    assert policy.evaluate('hey', ctx).risk_score == 0
    assert len(policy._attempts[(1, 1)]) == 2


def test_blocked_attempts_expire_and_split_evidence():
    classifier = Classifier()
    policy = SecurityPolicy(RuleDLPChecker(), classifier, URLs(), URLs())
    clock = [0]
    policy._clock = lambda: clock[0]
    ctx = MessageSecurityContext(1, 1)
    assert policy.evaluate('pineapple flour', ctx).reason_code == 'forbidden_term'
    assert policy.evaluate('cheese', ctx).risk_score == 10
    assert policy.evaluate('two cups', ctx).risk_score == 30
    assert classifier.calls[-1] == ('two cups', ('pineapple flour', 'cheese'))
    assert policy.evaluate('hey', MessageSecurityContext(2, 1)).risk_score == 0
    assert policy.evaluate('hey', MessageSecurityContext(1, 2)).risk_score == 0
    clock[0] = 300
    assert policy.evaluate('hey', ctx).risk_score == 0


@pytest.mark.parametrize('text,action', [
    ('hey', 'allow'), ('I love pizza', 'allow'), ('I have a pizza recipe', 'allow'),
    ('For chocolate cake mix flour sugar and bake for 20 minutes', 'allow'),
    ('then bake for 20 minutes', 'block'), ('200 g flour', 'block'),
])
def test_prompt_scope_and_current_context_with_mocked_model(monkeypatch, text, action):
    # Validates prompt and plumbing, not real-model semantic accuracy.
    def model(endpoint, payload, timeout):
        prompt = payload['system']
        for phrase in ('current text', 'pizza recipe', 'Allow unrelated recipes', 'neutral current message',
                       'ordinary pizza discussion', 'short current fragments'):
            assert phrase in prompt
        assert json.loads(payload['prompt']) == {'text': text, 'recent_attempts': ['pizza 200 g flour mix']}
        return json.dumps({'done': True, 'response': json.dumps({'action': action, 'risk_score': 60 if action == 'block' else 5})}).encode()
    monkeypatch.setattr(local_llm, '_call_model', model)
    policy = SecurityPolicy(RuleDLPChecker(), local_llm.OllamaRecipeClassifier(), URLs(), URLs())
    result = policy.evaluate(text, MessageSecurityContext(1, 1, ('pizza 200 g flour mix',)))
    assert result.action == action
    assert result.reason_code == ('recipe_blocked' if action == 'block' else 'security_allowed')


def test_stage_logs_and_real_url_adapter_mock_transport(caplog, monkeypatch):
    caplog.set_level(logging.INFO, logger='chat.security')
    monkeypatch.setattr(url_security, 'RATE_LIMIT_PER_MINUTE', 100)
    calls = []
    def handler(request):
        calls.append(request)
        assert request.url.path.startswith('/api/v3/domains/')
        assert request.headers['x-apikey'] == 'PRIVATE_KEY_MARKER'
        if 'timeout' in request.url.path:
            raise httpx.ReadTimeout('PRIVATE_FAILURE_MARKER')
        if 'limited' in request.url.path:
            return httpx.Response(429)
        return httpx.Response(200, json={'data': {'attributes': {
            'last_analysis_stats': {'malicious': 2 if 'bad' in request.url.path else 0, 'harmless': 4},
            'last_analysis_date': int(time.time())}}})
    checker = url_security.VirusTotalURLReputationChecker('PRIVATE_KEY_MARKER', httpx.Client(transport=httpx.MockTransport(handler)))
    policy = SecurityPolicy(RuleDLPChecker(), Classifier(), url_security.RegexURLExtractor(), checker)
    ctx = MessageSecurityContext(1, 1)
    try:
        assert policy.evaluate('PRIVATE_TEXT_MARKER', ctx).action == 'allow'
        assert len(calls) == 0
        for _ in range(2):
            assert policy.evaluate('https://safe.example.com/PRIVATE_PATH', ctx).action == 'allow'
        assert len(calls) == 1
        assert policy.evaluate('https://bad.example.com', ctx).reason_code == 'malicious_url'
        assert policy.evaluate('https://timeout.example.com', ctx).reason_code == 'reputation_unavailable'
        assert policy.evaluate('https://limited.example.com', ctx).reason_code == 'reputation_unavailable'
    finally:
        checker.close()
    logs = '\n'.join(record.message for record in caplog.records if record.name == 'chat.security')
    for marker in ('PRIVATE_', 'example.com', 'https://'):
        assert marker not in logs
    for expected in ('stage=window', 'stage=rules current_score=', 'window_score=',
                     'stage=llm called=False', 'stage=urls detected=False count=0',
                     'stage=url_check source=cache', 'stage=url_check source=api',
                     'status=url_safe', 'status=url_malicious', 'failure=timeout',
                     'failure=rate_limited_429', 'stage=final'):
        assert expected in logs
    ids = re.findall(r'attempt_id=(\w+) stage=attempt', logs)
    assert len(set(ids)) == 6
    for trace in ids:
        assert f'attempt_id={trace} stage=final' in logs


def test_llm_failure_logs_are_distinct_from_rules(monkeypatch, caplog):
    caplog.set_level(logging.INFO, logger='chat.security')
    def timeout(*args):
        raise TimeoutError('PRIVATE_MODEL_ERROR')
    monkeypatch.setattr(local_llm, '_call_model', timeout)
    policy = SecurityPolicy(RuleDLPChecker(), local_llm.OllamaRecipeClassifier(), URLs(), URLs())
    result = policy.evaluate('pizza 200 g', MessageSecurityContext(1, 1))
    assert result.reason_code == 'security_check_unavailable'
    assert 'current_score=30 window_score=30' in caplog.text
    assert 'stage=llm called=True action=block risk_score=99 failure=timeout' in caplog.text
    assert 'stage=final action=block final_score=99' in caplog.text
    assert 'PRIVATE_MODEL_ERROR' not in caplog.text


def test_url_review_and_missing_credentials_logs(caplog):
    caplog.set_level(logging.INFO, logger='chat.security')
    def missing_report(request):
        return httpx.Response(404)
    for key, reason, source in [('', 'reputation_unavailable', 'local'),
                                ('TEST_KEY', 'reputation_review_required', 'api')]:
        client = httpx.Client(transport=httpx.MockTransport(missing_report))
        checker = url_security.VirusTotalURLReputationChecker(key, client)
        try:
            policy = SecurityPolicy(RuleDLPChecker(), Classifier(), url_security.RegexURLExtractor(), checker)
            assert policy.evaluate('https://unknown.example.com', MessageSecurityContext(1, 1)).reason_code == reason
        finally:
            checker.close()
        assert f'stage=url_check source={source}' in caplog.text
    assert 'failure=missing_api_key' in caplog.text
    assert 'status=url_reputation_unknown' in caplog.text
    assert 'TEST_KEY' not in caplog.text


def test_concurrent_attempt_logs_do_not_mix(caplog):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    caplog.set_level(logging.INFO, logger='chat.security')
    barrier = Barrier(2)
    class WaitingClassifier(Classifier):
        def classify(self, text, previous):
            barrier.wait(timeout=5)
            return super().classify(text, previous)
    policy = SecurityPolicy(RuleDLPChecker(), WaitingClassifier(), URLs(), URLs())
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda user: policy.evaluate('pizza 200 g', MessageSecurityContext(user, 1)), [1, 2]))
    assert all(result.action == 'allow' for result in results)
    traces = {}
    for record in caplog.records:
        match = re.search(r'attempt_id=(\w+) stage=(\w+)', record.message)
        if match:
            traces.setdefault(match[1], []).append(match[2])
    assert len(traces) == 2
    assert all(stages == ['attempt', 'window', 'rules', 'llm', 'urls', 'final'] for stages in traces.values())
