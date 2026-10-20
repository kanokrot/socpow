import importlib.util

import pytest
import yaml

from src.detection.rule_generator import RuleGenerator
from src.detection.rule_validator import validate_rule


VALID_SIGMA = """title: Suspicious process
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: cmd.exe
  condition: selection
"""

VALID_YARA = """rule Suspicious_File {
    strings:
        $marker = "socpow-test"
    condition:
        $marker
}
"""


requires_pysigma = pytest.mark.skipif(
    importlib.util.find_spec('sigma') is None,
    reason='pySigma not installed',
)


@pytest.mark.parametrize(
    ('rule_type', 'content'),
    [
        ('kql', 'DeviceProcessEvents\n| where FileName == "cmd.exe"'),
        ('spl', 'index=main | search process_name="cmd.exe"'),
        ('xql', 'dataset = xdr_data | filter event_type = PROCESS'),
        ('dql', 'process.name:"cmd.exe" and event.code:1'),
    ],
)
def test_query_rule_basic_validation_accepts_balanced_content(rule_type, content):
    assert validate_rule(rule_type, content) == {
        'valid': True,
        'errors': [],
        'rule_type': rule_type,
    }


@pytest.mark.parametrize('rule_type', ['kql', 'spl', 'xql', 'dql'])
def test_query_rule_basic_validation_rejects_unbalanced_syntax(rule_type):
    result = validate_rule(rule_type, 'query | where field == "unterminated')

    assert result['valid'] is False
    assert result['rule_type'] == rule_type
    assert 'Unterminated " quote' in result['errors']


def test_sigma_uses_yaml_parser_and_requires_core_sigma_shape():
    assert validate_rule('sigma', VALID_SIGMA)['valid'] is True

    malformed = validate_rule('sigma', 'title: Test\ndetection: [')
    assert malformed['valid'] is False
    assert malformed['errors'][0].startswith('Sigma YAML syntax error:')

    missing_shape = validate_rule('sigma', 'title: Test')
    assert missing_shape['valid'] is False
    assert 'Sigma rule is missing required field: logsource' in missing_shape['errors']
    assert 'Sigma rule is missing required field: detection' in missing_shape['errors']


@pytest.mark.parametrize('ioc_type', ['ipv4', 'domain', 'url', 'sha256'])
@requires_pysigma
def test_sigma_generated_ioc_is_parsed_by_pysigma(ioc_type):
    content = RuleGenerator.generate_ioc_rules(
        '203.0.113.42', ioc_type, {}
    )['sigma']

    result = validate_rule('sigma', content)

    assert result['valid'] is True
    assert result['syntax_valid'] is True
    assert result['schema_valid'] is True
    assert result['status'] == 'pysigma_parsed'


@pytest.mark.parametrize(
    'invalid_case', ['missing_condition', 'unknown_modifier', 'missing_logsource',
                     'invalid_level', 'invalid_date', 'invalid_id']
)
@requires_pysigma
def test_sigma_pysigma_rejects_invalid_rules(invalid_case):
    document = yaml.safe_load(
        RuleGenerator.generate_ioc_rules(
            '203.0.113.42', 'ipv4', {}
        )['sigma']
    )

    if invalid_case == 'missing_condition':
        del document['detection']['condition']
    elif invalid_case == 'unknown_modifier':
        document['detection']['selection_dst'] = {
            'query|foo': '203.0.113.42'
        }
    elif invalid_case == 'missing_logsource':
        del document['logsource']
    elif invalid_case == 'invalid_level':
        document['level'] = 'not-a-level'
    elif invalid_case == 'invalid_date':
        document['date'] = 'not-a-date'
    elif invalid_case == 'invalid_id':
        document['id'] = 'not-a-uuid'

    result = validate_rule('sigma', yaml.safe_dump(document, sort_keys=False))

    assert result['valid'] is False
    assert result['syntax_valid'] is True
    assert result['schema_valid'] is False
    assert result['status'] == 'pysigma_rejected'
    assert result['errors']


@requires_pysigma
def test_sigma_unknown_condition_is_rejected():
    document = yaml.safe_load(
        RuleGenerator.generate_ioc_rules(
            '203.0.113.42', 'ipv4', {}
        )['sigma']
    )
    document['detection']['condition'] = 'selection_missing'

    result = validate_rule('sigma', yaml.safe_dump(document, sort_keys=False))

    assert result['valid'] is False
    assert result['status'] == 'pysigma_rejected'
    assert 'Sigma condition references undefined selection: selection_missing' in result['errors']


def _sigma_with_condition(condition, selections):
    document = {
        'title': 'Condition test',
        'logsource': {'category': 'process_creation'},
        'detection': dict(selections, condition=condition),
    }
    return yaml.safe_dump(document, sort_keys=False)


def test_sigma_condition_references_existing_selections():
    content = _sigma_with_condition(
        'selection_a and not selection_b',
        {
            'selection_a': {'Image': 'cmd.exe'},
            'selection_b': {'Image': 'powershell.exe'},
        },
    )
    result = validate_rule('sigma', content)
    assert result['valid'] is True


def test_sigma_condition_one_of_wildcard_requires_matching_selection():
    valid = validate_rule(
        'sigma',
        _sigma_with_condition(
            '1 of sel_*',
            {
                'sel_a': {'Image': 'cmd.exe'},
                'sel_b': {'Image': 'powershell.exe'},
            },
        ),
    )
    assert valid['valid'] is True

    invalid = validate_rule(
        'sigma',
        _sigma_with_condition(
            '1 of sel_*',
            {'selection_a': {'Image': 'cmd.exe'}},
        ),
    )
    assert invalid['valid'] is False
    assert invalid['status'] == 'pysigma_rejected'
    assert 'Sigma condition references undefined selection: sel_*' in invalid['errors']


def test_sigma_yaml_syntax_error_is_syntax_only():
    result = validate_rule('sigma', 'title: Test\ndetection: [')

    assert result['valid'] is False
    assert result['syntax_valid'] is False
    assert result['schema_valid'] is False
    assert result['status'] == 'syntax_only'


def test_yara_uses_yara_python_compiler():
    assert validate_rule('yara', VALID_YARA)['valid'] is True

    malformed = validate_rule('yara', 'rule Broken { condition: }')
    assert malformed['valid'] is False
    assert malformed['errors'][0].startswith('YARA syntax error:')


@pytest.mark.parametrize('rule_type', ['suricata', 'snort'])
def test_network_rule_structural_validation(rule_type):
    valid_rule = (
        'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
        '(msg:"SOCPOW test"; sid:1000001; rev:1;)'
    )
    assert validate_rule(rule_type, valid_rule)['valid'] is True

    invalid = validate_rule(rule_type, 'alert tcp $HOME_NET any')
    assert invalid['valid'] is False
    assert 'must contain an action, header, direction, and options' in invalid['errors'][0]


def test_firewall_structural_validation():
    valid = 'action=deny indicator_type=ipv4 indicator="203.0.113.5"'
    assert validate_rule('firewall', valid)['valid'] is True

    invalid = validate_rule('firewall', 'send this somewhere')
    assert invalid['valid'] is False
    assert invalid['errors'] == [
        'Firewall rule must use key/value entries or a recognized '
        'allow, deny, block, permit, or configuration command'
    ]


def test_empty_and_unsupported_rule_types_are_invalid():
    assert validate_rule('kql', '  ')['errors'] == [
        'Rule content must be a non-empty string'
    ]
    assert validate_rule('elastic-eql', 'process where true') == {
        'valid': False,
        'errors': ['Unsupported rule type: elastic-eql'],
        'rule_type': 'elastic-eql',
    }
