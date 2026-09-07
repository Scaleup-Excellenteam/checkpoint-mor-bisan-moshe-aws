"""Shared coordinator wired once by the server lifespan.

Integrator: create one SecurityPolicy(checker, classifier, extractor, reputation),
then evaluate(text, MessageSecurityContext(authenticated_user_id, room_id)) after
access/input checks and before persistence/broadcast. Persist only action=allow.
For names call checker.check('username'/'room_name', text) directly; never pass
passwords. Injected synchronous adapters must enforce their own I/O timeouts.

The coordinator owns attempt windows. context.recent_attempts seeds a new key
once (trusted server data only), never appends duplicates on subsequent calls.
Per-user/room locks order evaluations and all attempts, including blocked ones.
Unrelated windows can progress while an adapter is waiting on I/O.
Windows retain ten total attempts per user/room for five minutes.
Unresolved URL review is conservatively blocked as reputation_review_required.
No provider reason/details are copied into the final result, preventing leakage.
"""
from collections import deque
from threading import RLock
import time
import uuid
from chat_system.security_logging import attempt_id, llm_failure, stage

from chat_system.security_contracts import (
    ALLOW_MAX_SCORE, CONTEXT_WINDOW_SIZE, DeterministicDLPChecker,
    MessageSecurityContext, RecipeClassifier, SecurityDecision,
    URLExtractor, URLReputationChecker,
)


class SecurityPolicy:
    def __init__(self, checker: DeterministicDLPChecker, classifier: RecipeClassifier,
                 extractor: URLExtractor, reputation: URLReputationChecker):
        self.checker = checker
        self.classifier = classifier
        self.extractor = extractor
        self.reputation = reputation
        self._attempts = {}
        self._lock = RLock()
        self._key_locks = {}
        self._timestamps = {}
        self._clock = time.monotonic  # Injectable without changing the public constructor.

    @staticmethod
    def _decision(value):
        if (not isinstance(value, SecurityDecision)
                or value.action not in ('allow', 'review', 'block')
                or type(value.risk_score) is not int or not 0 <= value.risk_score <= 100):
            raise ValueError('Invalid security decision')
        return value

    def evaluate(self, text: str, context: MessageSecurityContext) -> SecurityDecision:
        trace = attempt_id.set(uuid.uuid4().hex)
        try:
            stage('attempt', user_id=context.user_id, room_id=context.room_id)
            result = self._evaluate(text, context)
            stage('final', action=result.action, final_score=result.risk_score,
                  reason=result.reason_code)
            return result
        finally:
            attempt_id.reset(trace)

    def _evaluate(self, text, context):
        if not isinstance(text, str):
            raise TypeError('text must be a string')
        key = (context.user_id, context.room_id)
        with self._lock:
            key_lock = self._key_locks.setdefault(key, RLock())
        with key_lock:
            now = self._clock()
            if key not in self._attempts:
                self._attempts[key] = deque(context.recent_attempts[-(CONTEXT_WINDOW_SIZE - 1):],
                                            maxlen=CONTEXT_WINDOW_SIZE)
                self._timestamps[key] = deque([now] * len(self._attempts[key]), maxlen=CONTEXT_WINDOW_SIZE)
            attempts = self._attempts[key]
            timestamps = self._timestamps[key]
            while attempts and (now - timestamps[0] >= 300 or len(attempts) >= CONTEXT_WINDOW_SIZE):
                attempts.popleft()
                timestamps.popleft()
            previous = tuple(attempts)
            attempts.append(text)  # Includes every attempt, even failures/hard blocks.
            timestamps.append(now)
            stage('window', size=len(attempts), oldest_age_seconds=round(now - timestamps[0], 3))
            current = MessageSecurityContext(context.user_id, context.room_id, previous)
            rules = self._decision(self.checker.check('message', text, current))
            score = rules.risk_score
            current_score = self._decision(self.checker.check('message', text)).risk_score if hasattr(self.checker, '_soft_score') else 'unavailable'
            counts = self.checker._soft_score(text, current)[1] if hasattr(self.checker, '_soft_score') else {}
            stage('rules', current_score=current_score, window_score=score, **counts)
            if rules.action == 'block' or score == 100:
                stage('llm', called=False, status='hard_block')
                stage('urls', detected='not_evaluated', count='not_evaluated', status='hard_block')
                return SecurityDecision('block', 'forbidden_term', score, 'policy')
            if score > ALLOW_MAX_SCORE or rules.action == 'review':
                started = time.monotonic()
                failure_token = llm_failure.set('none')
                try:
                    verdict = self._decision(self.classifier.classify(text, previous))
                    if verdict.action == 'review' or verdict.risk_score > 99:
                        raise ValueError('Classifier must resolve review')
                except Exception:
                    stage('llm', called=True, action='block', failure='adapter_error', duration_ms=round((time.monotonic()-started)*1000, 2))
                    stage('urls', detected='not_evaluated', count='not_evaluated', status='llm_failure')
                    return SecurityDecision('block', 'security_check_unavailable', score, 'policy')
                finally:
                    failure = llm_failure.get()
                    llm_failure.reset(failure_token)
                stage('llm', called=True, action=verdict.action, risk_score=verdict.risk_score,
                      failure=failure, duration_ms=round((time.monotonic()-started)*1000, 2))
                if verdict.action == 'block':
                    stage('urls', detected='not_evaluated', count='not_evaluated', status='llm_block')
                    reason = ('security_check_unavailable' if verdict.reason_code == 'security_check_unavailable'
                              else 'recipe_blocked')
                    return SecurityDecision('block', reason, max(score, verdict.risk_score), 'policy')
            else:
                stage('llm', called=False, status='below_threshold')
            try:
                urls = self.extractor.extract(text)  # Original, not DLP-normalized text.
                if not isinstance(urls, list) or not all(isinstance(url, str) for url in urls):
                    raise ValueError('Invalid URL extraction result')
                stage('urls', detected=bool(urls), count=len(set(urls)), status='extracted')
            except Exception:
                stage('urls', detected='unknown', count='unknown', status='extraction_failure')
                return SecurityDecision('block', 'reputation_unavailable', score, 'policy')
            review = malicious = unavailable = False
            for url in dict.fromkeys(urls):
                started = time.monotonic()
                try:
                    verdict = self._decision(self.reputation.check(url))
                    score = max(score, verdict.risk_score)
                    if verdict.action == 'block':
                        if verdict.reason_code == 'reputation_unavailable':
                            unavailable = True
                        else:
                            malicious = True
                    review |= verdict.action == 'review'
                except Exception:
                    stage('url_check', source='unknown', status='reputation_unavailable',
                          failure='adapter_error', duration_ms=round((time.monotonic()-started)*1000, 2))
                    unavailable = True
            # Check every URL; a known malicious URL takes precedence over failures.
            if malicious:
                return SecurityDecision('block', 'malicious_url', score, 'policy')
            if unavailable:
                return SecurityDecision('block', 'reputation_unavailable', score, 'policy')
            if review:
                return SecurityDecision('block', 'reputation_review_required', score, 'policy')
            return SecurityDecision('allow', 'security_allowed', score, 'policy')
