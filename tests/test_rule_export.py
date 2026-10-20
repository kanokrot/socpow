import io
import zipfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.web.analysis_manager import AnalysisManager
from src.web.routes import reports


SIGMA_RULE = """title: SOCPOW export test
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: cmd.exe
  condition: selection
"""

YARA_RULE = """rule SOCPOW_Export_Test {
    strings:
        $marker = "socpow-export-test"
    condition:
        $marker
}
"""

SURICATA_RULE = (
    'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
    '(msg:"SOCPOW export test"; sid:1000001; rev:1;)'
)


@pytest.fixture
def report_client(tmp_path):
    reports._rule_export_states.clear()
    app = FastAPI()
    from src.web.auth import get_current_user
    app.dependency_overrides[get_current_user] = lambda: {
        "id": 1,
        "email": "admin@example.test",
        "username": "admin",
        "role": "admin",
        "is_active": 1,
    }
    app.state.analysis_manager = AnalysisManager(
        db_path=str(tmp_path / 'analysis_jobs.db')
    )
    app.include_router(reports.router, prefix='/api/reports')
    job_id = app.state.analysis_manager.create_job('ioc', {'value': 'test'})
    app.state.analysis_manager.complete_job(
        job_id,
        {
            'detection_rules': {
                'kql': 'DeviceProcessEvents\n| take 10',
                'sigma': SIGMA_RULE,
                'yara': YARA_RULE,
                'suricata': SURICATA_RULE,
            }
        },
    )
    with TestClient(app) as client:
        yield client, app.state.analysis_manager, job_id
    reports._rule_export_states.clear()


def test_rule_starts_pending_and_download_requires_approval(report_client):
    client, _, job_id = report_client

    status = client.get(f'/api/reports/{job_id}/rules/kql/status')
    denied = client.get(f'/api/reports/{job_id}/rules/kql/download')

    assert status.status_code == 200
    assert status.json()['status'] == 'pending_export'
    assert denied.status_code == 403
    assert denied.json()['detail'] == (
        'KQL rule export requires explicit human approval'
    )


def test_approval_validates_and_individual_download_uses_expected_extension(
    report_client,
):
    client, _, job_id = report_client

    approval = client.post(
        f'/api/reports/{job_id}/rules/yara/approve',
        json={'approved_by': 'forged'},
    )
    download = client.get(f'/api/reports/{job_id}/rules/yara/download')

    assert approval.status_code == 200
    assert approval.json()['status'] == 'approved'
    assert approval.json()['approved_by'] == 'admin'
    assert approval.json()['approved_at']
    assert approval.json()['validation']['valid'] is True
    assert download.status_code == 200
    assert download.content.decode('utf-8').rstrip() == YARA_RULE.rstrip()
    assert f'analysis-{job_id}-yara.yar' in download.headers['content-disposition']


def test_approval_without_body_uses_authenticated_username(report_client):
    client, _, job_id = report_client

    approval = client.post(
        f'/api/reports/{job_id}/rules/kql/approve',
    )

    assert approval.status_code == 200
    assert approval.json()['approved_by'] == 'admin'


def test_invalid_rule_cannot_be_approved_or_exported(report_client):
    client, manager, job_id = report_client
    manager.complete_job(
        job_id,
        {'detection_rules': {'kql': 'DeviceEvents | where Name == "broken'}},
    )

    approval = client.post(
        f'/api/reports/{job_id}/rules/kql/approve',
        json={'approved_by': 'analyst-02'},
    )
    download = client.get(f'/api/reports/{job_id}/rules/kql/download')

    assert approval.status_code == 422
    assert approval.json()['detail']['message'] == (
        'Rule validation failed; export was not approved'
    )
    assert approval.json()['detail']['validation']['valid'] is False
    assert download.status_code == 403


def test_zip_requires_approval_for_every_selected_rule_and_contains_files(
    report_client,
):
    client, _, job_id = report_client
    client.post(
        f'/api/reports/{job_id}/rules/sigma/approve',
        json={'approved_by': 'reviewer'},
    )

    denied = client.get(
        f'/api/reports/{job_id}/rules/export/zip',
        params={'rule_types': 'sigma,yara'},
    )
    assert denied.status_code == 403
    assert denied.json()['detail'] == (
        'YARA rule export requires explicit human approval'
    )

    client.post(
        f'/api/reports/{job_id}/rules/yara/approve',
        json={'approved_by': 'reviewer'},
    )
    exported = client.get(
        f'/api/reports/{job_id}/rules/export/zip',
        params={'rule_types': 'sigma,yara'},
    )

    assert exported.status_code == 200
    assert exported.headers['content-type'] == 'application/zip'
    with zipfile.ZipFile(io.BytesIO(exported.content)) as archive:
        assert archive.namelist() == ['sigma.yml', 'yara.yar']
        assert archive.read('sigma.yml').decode('utf-8').rstrip() == SIGMA_RULE.rstrip()
        assert archive.read('yara.yar').decode('utf-8').rstrip() == YARA_RULE.rstrip()


def test_mark_deployed_is_record_only_and_requires_prior_approval(report_client):
    client, _, job_id = report_client

    denied = client.post(
        f'/api/reports/{job_id}/rules/suricata/mark-deployed',
        json={'deployed_by': 'forged'},
    )
    assert denied.status_code == 403

    client.post(
        f'/api/reports/{job_id}/rules/suricata/approve',
        json={'approved_by': 'analyst-03'},
    )
    deployed = client.post(
        f'/api/reports/{job_id}/rules/suricata/mark-deployed',
        json={'deployed_by': 'forged'},
    )

    assert deployed.status_code == 200
    assert deployed.json()['status'] == 'deployed'
    assert deployed.json()['deployed_by'] == 'admin'
    assert deployed.json()['deployed_at']
    assert deployed.json()['approved_by'] == 'admin'


def test_changed_rule_content_returns_to_pending_export(report_client):
    client, manager, job_id = report_client
    client.post(
        f'/api/reports/{job_id}/rules/kql/approve',
        json={'approved_by': 'analyst-04'},
    )
    manager.complete_job(
        job_id,
        {'detection_rules': {'kql': 'DeviceNetworkEvents\n| take 20'}},
    )

    denied = client.get(f'/api/reports/{job_id}/rules/kql/download')
    status = client.get(f'/api/reports/{job_id}/rules/kql/status')

    assert denied.status_code == 403
    assert status.json()['status'] == 'pending_export'
    assert status.json()['approved_by'] is None


def test_edit_rule_persists_and_invalidates_prior_approval(report_client):
    client, manager, job_id = report_client
    original = 'DeviceProcessEvents\n| take 10'
    edited = 'DeviceProcessEvents\n| where FileName == "cmd.exe"'
    manager.complete_job(
        job_id,
        {
            'detection_rules': {'kql': original},
            'untouched': {'keep': True},
        },
    )

    approval = client.post(
        f'/api/reports/{job_id}/rules/kql/approve',
        json={'approved_by': 'analyst-edit'},
    )
    assert approval.status_code == 200

    edited_response = client.put(
        f'/api/reports/{job_id}/rules/kql',
        json={'content': edited},
    )
    assert edited_response.status_code == 200
    assert edited_response.json() == {
        'success': True,
        'rule_type': 'kql',
        'validation': {
            'valid': True,
            'errors': [],
            'rule_type': 'kql',
        },
    }

    status = client.get(f'/api/reports/{job_id}/rules/kql/status')
    assert status.status_code == 200
    assert status.json()['status'] == 'pending_export'
    assert status.json()['approved_by'] is None

    reloaded_manager = AnalysisManager(db_path=str(manager._db_path))
    reloaded_job = reloaded_manager.get_job(job_id)
    assert reloaded_job['result']['detection_rules']['kql'] == edited
    assert reloaded_job['result']['untouched'] == {'keep': True}


def test_edit_invalid_rule_returns_422_and_preserves_existing_content(
    report_client,
):
    client, manager, job_id = report_client
    original = manager.get_job(job_id)['result']['detection_rules']['kql']

    response = client.put(
        f'/api/reports/{job_id}/rules/kql',
        json={'content': 'DeviceEvents | where Name == "unterminated'},
    )

    assert response.status_code == 422
    assert response.json()['detail']['message'] == (
        'Rule validation failed; content was not saved'
    )
    assert response.json()['detail']['validation']['valid'] is False
    assert manager.get_job(job_id)['result']['detection_rules']['kql'] == original


def test_edit_missing_rule_returns_404(report_client):
    client, _, job_id = report_client

    response = client.put(
        f'/api/reports/{job_id}/rules/firewall',
        json={'content': 'action=deny indicator_type=ipv4 indicator="203.0.113.5"'},
    )

    assert response.status_code == 404


def test_edit_rule_requires_string_content_at_schema(report_client):
    client, manager, job_id = report_client
    original = manager.get_job(job_id)['result']['detection_rules']['kql']

    response = client.put(
        f'/api/reports/{job_id}/rules/kql',
        json={'content': ['DeviceEvents | take 1']},
    )

    assert response.status_code == 422
    assert manager.get_job(job_id)['result']['detection_rules']['kql'] == original


def test_update_detection_rule_returns_false_without_detection_rules(tmp_path):
    manager = AnalysisManager(db_path=str(tmp_path / 'analysis_jobs.db'))
    job_id = manager.create_job('ioc', {'value': 'test'})
    manager.complete_job(job_id, {'summary': 'no rules'})

    assert manager.update_detection_rule(job_id, 'kql', 'DeviceEvents') is False
    assert manager.get_job(job_id)['result'] == {'summary': 'no rules'}
