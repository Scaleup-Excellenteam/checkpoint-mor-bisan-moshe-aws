"""Deterministic rules only; no network, database, or logging.

Protected-term entries contain term, aliases, abbreviations, one_edit_variants,
and fuzzy (default False). Distance-one matching is opt-in for protected words
of at least five characters, never abbreviations or arbitrary vocabulary.
Separators may occur between letters, but matches must have word boundaries.
Recipe weights are fixed by the shared decisions. Ingredients count distinctly;
"several categories" means at least three in a single attempt. Other category
bonuses count once over current + up to ten prior attempts. Hard matching checks
only the current attempt, so old blocked terms do not permanently poison a room.
"""
import json
from pathlib import Path
import re
import unicodedata

from chat_system.security_contracts import (
    ALLOW_MAX_SCORE, CONTEXT_WINDOW_SIZE, SecurityDecision, MessageSecurityContext,
    ProtectedField,
)


def normalize(text: str) -> str:
    """NFKC/casefold and removal of format controls and variation selectors."""
    if not isinstance(text, str):
        raise TypeError('text must be a string')
    return ''.join(c for c in unicodedata.normalize('NFKC', text).casefold()
                   if unicodedata.category(c) != 'Cf'
                   and not ('\ufe00' <= c <= '\ufe0f' or '\U000e0100' <= c <= '\U000e01ef'))


def distance_one(a: str, b: str) -> bool:
    """Levenshtein distance <= 1; bounded scan rather than broad fuzzy search."""
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) <= 1
    if len(a) > len(b):
        a, b = b, a
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return a[i:] == b[i + 1:]
    return True


class RuleDLPChecker:
    def __init__(self, rules_path: str | Path = Path(__file__).resolve().parents[1] / 'config' / 'dlp_rules.json'):
        rules = json.loads(Path(rules_path).read_text(encoding='utf-8-sig'))
        if not rules['protected_terms']:
            raise ValueError('Configure protected_terms in dlp_rules.json before use')
        self.translation = str.maketrans({normalize(symbol): normalize(target)
                                         for symbol, target in rules['substitutions'].items()})
        self.ambiguous = rules.get('ambiguous_substitutions', {})
        separators = rules['separators']
        self.separators = set(separators)
        gap = '[' + re.escape(separators) + ']*'
        self.hard_patterns = []
        self.fuzzy_terms = []
        for entry in rules['protected_terms']:
            forms = [entry['term'], *entry.get('aliases', []),
                     *entry.get('abbreviations', []), *entry.get('one_edit_variants', [])]
            for form in forms:
                compact = ''.join(c for c in self._hard_text(form) if c not in self.separators)
                if not compact or not compact.isalnum():
                    raise ValueError('Protected forms must normalize to letters/digits')
                letters = []
                for char in compact:
                    alternatives = char + ''.join(symbol for symbol, targets in self.ambiguous.items()
                                                   if char in targets)
                    letters.append('[' + re.escape(alternatives) + ']')
                self.hard_patterns.append(re.compile(r'(?<![^\W_])' + gap.join(letters) + r'(?![^\W_])'))
            if entry.get('fuzzy', False):
                term = self._hard_text(entry['term'])
                if not term.isalpha() or len(term) < 5:
                    raise ValueError('Fuzzy protected terms must be single words of length >= 5')
                self.fuzzy_terms.append(term)
        recipe = rules['recipe']
        self.vocabulary = {key: {normalize(word) for word in recipe[key]}
                           for key in ('anchors', 'ingredients', 'actions', 'sequences')}
        self.quantity = re.compile(recipe['quantity_pattern'])
        self.time_temperature = re.compile(recipe['time_temperature_pattern'])

    def _hard_text(self, text):
        return normalize(text).translate(self.translation)

    def check(self, field_name: ProtectedField, text: str,
              context: MessageSecurityContext | None = None) -> SecurityDecision:
        if field_name not in ('message', 'username', 'room_name'):
            raise ValueError('Unsupported protected field')
        hard_text = self._hard_text(text)
        if (any(pattern.search(hard_text) for pattern in self.hard_patterns)
                or any(distance_one(token, term) for token in re.findall(r'[^\W_]+', hard_text)
                       for term in self.fuzzy_terms)):
            return SecurityDecision('block', 'forbidden_term', 100, 'rules')
        if field_name != 'message':
            return SecurityDecision('allow', 'content_allowed', 0, 'rules')
        prior = context.recent_attempts[-CONTEXT_WINDOW_SIZE:] if context else ()
        features = set()
        ingredients = set()
        multiple = False
        for attempt in (*prior, text):
            normalized = normalize(attempt)
            words = set(re.findall(r'[^\W_]+', normalized))
            present = {key for key, vocabulary in self.vocabulary.items() if words & vocabulary}
            ingredients.update(words & self.vocabulary['ingredients'])
            if self.quantity.search(normalized):
                present.add('quantity')
            if self.time_temperature.search(normalized):
                present.add('time_temperature')
            multiple |= len(present) >= 3
            features.update(present)
        score = (10 * ('anchors' in features) + min(len(ingredients) * 5, 20)
                 + 20 * ('quantity' in features) + 15 * ('actions' in features)
                 + 15 * ('time_temperature' in features) + 10 * ('sequences' in features)
                 + 10 * multiple)
        score = min(score, 99)
        return SecurityDecision('allow' if score <= ALLOW_MAX_SCORE else 'review',
                                'recipe_low_risk' if score <= ALLOW_MAX_SCORE else 'recipe_review',
                                score, 'rules')
