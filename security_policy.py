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
Windows retain ten strings per user/room, with no expiry or bound on key count.
Unresolved URL review is conservatively blocked as reputation_review_required.
No provider reason/details are copied into the final result, preventing leakage.
"""
from collections import deque
from threading import RLock

from security_contracts import (
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

    @staticmethod
    def _decision(value):
        if (not isinstance(value, SecurityDecision)
                or value.action not in ('allow', 'review', 'block')
                or type(value.risk_score) is not int or not 0 <= value.risk_score <= 100):
            raise ValueError('Invalid security decision')
        return value

    def evaluate(self, text: str, context: MessageSecurityContext) -> SecurityDecision:
        if not isinstance(text, str):
            raise TypeError('text must be a string')
        key = (context.user_id, context.room_id)
        with self._lock:
            key_lock = self._key_locks.setdefault(key, RLock())
        with key_lock:
            if key not in self._attempts:
                self._attempts[key] = deque(context.recent_attempts[-CONTEXT_WINDOW_SIZE:],
                                            maxlen=CONTEXT_WINDOW_SIZE)
            attempts = self._attempts[key]
            previous = tuple(attempts)
            attempts.append(text)  # Includes every attempt, even failures/hard blocks.
            current = MessageSecurityContext(context.user_id, context.room_id, previous)
            rules = self._decision(self.checker.check('message', text, current))
            score = rules.risk_score
            if rules.action == 'block' or score == 100:
                return SecurityDecision('block', 'forbidden_term', score, 'policy')
            if score > ALLOW_MAX_SCORE or rules.action == 'review':
                try:
                    verdict = self._decision(self.classifier.classify(text, previous))
                    if verdict.action == 'review' or verdict.risk_score > 99:
                        raise ValueError('Classifier must resolve review')
                except Exception:
                    return SecurityDecision('block', 'security_check_unavailable', score, 'policy')
                if verdict.action == 'block':
                    reason = ('security_check_unavailable' if verdict.reason_code == 'security_check_unavailable'
                              else 'recipe_blocked')
                    return SecurityDecision('block', reason, max(score, verdict.risk_score), 'policy')
            try:
                urls = self.extractor.extract(text)  # Original, not DLP-normalized text.
                if not isinstance(urls, list) or not all(isinstance(url, str) for url in urls):
                    raise ValueError('Invalid URL extraction result')
            except Exception:
                return SecurityDecision('block', 'reputation_unavailable', score, 'policy')
            review = malicious = unavailable = False
            for url in dict.fromkeys(urls):
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
                    unavailable = True
            # Check every URL; a known malicious URL takes precedence over failures.
            if malicious:
                return SecurityDecision('block', 'malicious_url', score, 'policy')
            if unavailable:
                return SecurityDecision('block', 'reputation_unavailable', score, 'policy')
            if review:
                return SecurityDecision('block', 'reputation_review_required', score, 'policy')
            return SecurityDecision('allow', 'security_allowed', score, 'policy')
