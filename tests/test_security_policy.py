import json
from pathlib import Path

import pytest

from dlp import RuleDLPChecker
from security_contracts import MessageSecurityContext, SecurityDecision
from security_policy import SecurityPolicy


def decision(action='allow', score=0, source='rules', reason='test'):
    return SecurityDecision(action, reason, score, source, {'raw': 'must never leak'})


class Checker:
    def __init__(self, result=None):
        self.result = result or decision()
        self.calls = []

    def check(self, field, text, context):
        self.calls.append((field, text, context))
        return self.result


class Classifier:
    def __init__(self, result=None, failure=None):
        self.result = result or decision(source='local_llm')
        self.failure = failure
        self.calls = []

    def classify(self, text, previous):
        self.calls.append((text, previous))
        if self.failure:
            raise self.failure
        return self.result


class URLs:
    def __init__(self, result=None, failure=None):
        self.result = result or decision(source='url_reputation')
        self.failure = failure
        self.original = []
        self.checked = []

    def extract(self, text):
        self.original.append(text)
        return ['https://example.test/A', 'https://example.test/A'] if 'https://' in text else []

    def check(self, url):
        self.checked.append(url)
        if self.failure:
            raise self.failure
        return self.result


@pytest.mark.parametrize('score,call,action', [(0, False, 'allow'), (29, False, 'allow'),
    (30, True, 'allow'), (99, True, 'allow'), (100, False, 'block')])
def test_thresholds(score, call, action):
    checker, llm, urls = Checker(decision(score=score)), Classifier(), URLs()
    policy = SecurityPolicy(checker, llm, urls, urls)
    result = policy.evaluate('hello', MessageSecurityContext(1, 1))
    assert result.action == action and bool(llm.calls) == call
    assert result.details == {}


@pytest.mark.parametrize('failure', [TimeoutError('private text'), RuntimeError('private key')])
def test_classifier_failure(failure):
    policy = SecurityPolicy(Checker(decision('review', 30)), Classifier(failure=failure), URLs(), URLs())
    result = policy.evaluate('secret', MessageSecurityContext(1, 1))
    assert result.reason_code == 'security_check_unavailable' and result.action == 'block'
    assert 'private' not in repr(result) and 'secret' not in repr(result)


@pytest.mark.parametrize('action,reason', [('allow', 'security_allowed'),
    ('review', 'reputation_review_required'), ('block', 'malicious_url')])
def test_combined_and_original_url(action, reason):
    llm = Classifier()
    urls = URLs(decision(action, 50, 'url_reputation'))
    policy = SecurityPolicy(Checker(decision('review', 30)), llm, urls, urls)
    text = 'MixedCase https://example.test/A'
    result = policy.evaluate(text, MessageSecurityContext(1, 1))
    assert result.reason_code == reason
    assert urls.original == [text] and urls.checked == ['https://example.test/A']
    assert len(llm.calls) == 1 and result.details == {}


def test_hard_and_llm_block_short_circuit():
    for rules, llm_result, reason in [(decision('block', 100), decision(), 'forbidden_term'),
                                     (decision('review', 50), decision('block', 80), 'recipe_blocked')]:
        llm, urls = Classifier(llm_result), URLs()
        result = SecurityPolicy(Checker(rules), llm, urls, urls).evaluate('https://example.test', MessageSecurityContext(1, 1))
        assert result.reason_code == reason and result.action == 'block'
        assert urls.original == []
        if rules.action == 'block': assert llm.calls == []


def test_provider_failure():
    urls = URLs(failure=TimeoutError('private key'))
    result = SecurityPolicy(Checker(), Classifier(), urls, urls).evaluate('https://example.test', MessageSecurityContext(1, 1))
    assert result.action == 'block' and result.reason_code == 'reputation_unavailable'
    assert result.details == {}


def test_window_isolation_cap_and_blocked_attempts():
    checker, urls = Checker(decision('block', 100)), URLs()
    policy = SecurityPolicy(checker, Classifier(), urls, urls)
    for i in range(12): policy.evaluate(str(i), MessageSecurityContext(1, 1))
    assert checker.calls[-1][2].recent_attempts == tuple(map(str, range(1, 11)))
    assert tuple(policy._attempts[(1, 1)]) == tuple(map(str, range(2, 12)))
    for ctx in (MessageSecurityContext(2, 1), MessageSecurityContext(1, 2)):
        policy.evaluate('other', ctx)
        assert checker.calls[-1][2].recent_attempts == ()


def test_real_checker_split_attempts(tmp_path):
    llm, urls = Classifier(), URLs()
    rules = json.loads(Path('dlp_rules.json').read_text(encoding='utf-8-sig'))
    rules['protected_terms'] = [{'term': 'moonstone'}]
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps(rules), encoding='utf-8')
    policy = SecurityPolicy(RuleDLPChecker(path), llm, urls, urls)
    assert policy.evaluate('pizza', MessageSecurityContext(1, 1)).action == 'allow'
    policy.evaluate('200 g', MessageSecurityContext(2, 1))
    assert llm.calls == []
    policy.evaluate('200 g', MessageSecurityContext(1, 1))
    assert llm.calls == [('200 g', ('pizza',))]


def test_seed_once_and_invalid_adapter():
    checker, urls = Checker(decision('review', 30)), URLs()
    policy = SecurityPolicy(checker, Classifier(decision('review', 40)), urls, urls)
    ctx = MessageSecurityContext(1, 1, ('seed',))
    assert policy.evaluate('first', ctx).reason_code == 'security_check_unavailable'
    policy.evaluate('second', ctx)
    assert checker.calls[-1][2].recent_attempts == ('seed', 'first')


@pytest.mark.parametrize('component,reason', [('llm', 'security_check_unavailable'),
                                            ('url', 'reputation_unavailable')])
def test_reported_unavailability(component, reason):
    llm = Classifier(decision('block', 30, 'local_llm', reason)) if component == 'llm' else Classifier()
    urls = URLs(decision('block', 50, 'url_reputation', reason))
    policy = SecurityPolicy(Checker(decision('review', 30)), llm, urls, urls)
    assert policy.evaluate('https://example.test', MessageSecurityContext(1, 1)).reason_code == reason


def test_extraction_failure_and_invalid_verdict():
    class BrokenURLs(URLs):
        def extract(self, text):
            raise RuntimeError('secret')
    for extractor, reputation in ((BrokenURLs(), URLs()), (URLs(), URLs(result='invalid'))):
        result = SecurityPolicy(Checker(), Classifier(), extractor, reputation).evaluate(
            'https://example.test', MessageSecurityContext(1, 1))
        assert result.reason_code == 'reputation_unavailable'
        assert result.details == {}


def test_production_hard_match_never_calls_llm_or_provider():
    llm, urls = Classifier(), URLs()
    policy = SecurityPolicy(RuleDLPChecker(), llm, urls, urls)
    result = policy.evaluate('p!ne@pple https://example.test', MessageSecurityContext(1, 1))
    assert result.reason_code == 'forbidden_term' and result.risk_score == 100
    assert llm.calls == [] and urls.original == [] and urls.checked == []


def test_pizza_chat_vs_recipe_window():
    llm, urls = Classifier(), URLs()
    policy = SecurityPolicy(RuleDLPChecker(), llm, urls, urls)
    context = MessageSecurityContext(7, 3)
    for text in ('I love pizza', 'tomato and cheese', 'great sauce'):
        result = policy.evaluate(text, context)
        assert result.action == 'allow' and result.risk_score < 30
    assert llm.calls == []
    result = policy.evaluate('then add 200 g flour and bake for 20 minutes', context)
    assert 30 <= result.risk_score <= 99
    assert llm.calls == [('then add 200 g flour and bake for 20 minutes',
                          ('I love pizza', 'tomato and cheese', 'great sauce'))]
    # A high recipe score is reviewed, not deterministically blocked.
    assert result.action == 'allow'
