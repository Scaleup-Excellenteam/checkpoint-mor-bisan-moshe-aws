import json
from pathlib import Path

import pytest
from dlp import RuleDLPChecker, distance_one, normalize
from security_contracts import MessageSecurityContext


@pytest.fixture
def checker(tmp_path):
    rules = json.loads(Path('dlp_rules.json').read_text(encoding='utf-8-sig'))
    # Synthetic protected vocabulary, not an invented production policy.
    rules['protected_terms'] = [dict(term='moonstone', aliases=['lunar gem'],
                                     abbreviations=['mns'], one_edit_variants=['moonstnoe'], fuzzy=True)]
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps(rules), encoding='utf-8')
    return RuleDLPChecker(path)


@pytest.mark.parametrize('text', ['moonstone', 'MOONSTONE', 'lunar gem', 'mns',
    'm o o n s t o n e', 'moon_stone', 'moon-stone', 'moon.stone', 'moon\u200bstone',
    'ｍｏｏｎｓｔｏｎｅ', 'm00nstone', 'mооnstone', 'moonston', 'moonstxne', 'moonstoone', 'moonstnoe'])
@pytest.mark.parametrize('field', ['message', 'username', 'room_name'])
def test_hard_variants(checker, text, field):
    result = checker.check(field, text)
    assert (result.action, result.risk_score, result.reason_code) == ('block', 100, 'forbidden_term')
    assert result.details == {}


@pytest.mark.parametrize('text', ['moonlight', 'milestone', 'moonstonesmith', 'amnsz',
                                  'm n', 'lunar geometry', 'stone moon', 'hello world'])
def test_false_positives(checker, text):
    assert checker.check('message', text).action == 'allow'


def test_scoring(checker):
    examples = [('hello', 0), ('pizza', 10), ('flour flour', 5),
                ('flour water yeast salt sugar', 20), ('200 g', 20), ('knead', 15),
                ('20 minutes', 15), ('200°C', 15), ('first then next', 10),
                ('pizza 200 g', 30), ('pizza flour knead', 40),
                ('first pizza flour water yeast salt 200 g knead 20 minutes', 99)]
    for text, score in examples:
        result = checker.check('message', text)
        assert result.risk_score == score, text
        assert result.action == ('allow' if score < 30 else 'review')
    assert checker.check('room_name', 'pizza 200 g knead').risk_score == 0
    with pytest.raises(ValueError): checker.check('password', 'moonstone')


def test_split_and_cap(checker):
    context = MessageSecurityContext(1, 1, ('pizza', '200 g'))
    assert checker.check('message', 'knead', context).risk_score == 45
    context = MessageSecurityContext(1, 1, ('pizza',) + ('hello',) * 10)
    assert checker.check('message', '200 g', context).risk_score == 20
    # Old hard matches remain context but do not hard-block later harmless text.
    assert checker.check('message', 'hello', MessageSecurityContext(1, 1, ('moonstone',))).action == 'allow'


def test_distance_and_unicode():
    assert distance_one('abcd', 'abc') and distance_one('abc', 'abcd')
    assert distance_one('abcd', 'abxd') and not distance_one('abcd', 'axyd')
    assert normalize('Ａ\u200bB\ufe0f') == 'ab'


def test_missing_vocabulary_fails_explicitly(tmp_path):
    rules = json.loads(Path('dlp_rules.json').read_text(encoding='utf-8-sig'))
    rules['protected_terms'] = []
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps(rules), encoding='utf-8')
    with pytest.raises(ValueError, match='Configure protected_terms'):
        RuleDLPChecker(path)
