"""Draft shape/consistency tests only; all protocol evidence here is synthetic."""
import copy
import json
import unittest
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]


class DraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validators = {}
        for name in ('evidence-submission', 'verification-result'):
            schema = json.loads((ROOT / f'packages/attestation-contracts/{name}-draft.schema.json').read_text())
            Draft202012Validator.check_schema(schema)
            cls.validators[name] = Draft202012Validator(schema)
        cls.request = json.loads((ROOT / 'tests/fixtures/synthetic-submission-draft.json').read_text())
        cls.result = json.loads((ROOT / 'tests/fixtures/synthetic-result-draft.json').read_text())

    def invalid(self, payload):
        self.assertTrue(list(self.validators[payload['kind']].iter_errors(payload)))

    def test_labeled_incomplete_synthetic_fixtures(self):
        for payload in (self.request, self.result):
            self.assertEqual(payload['origin'], 'synthetic')
            self.validators[payload['kind']].validate(payload)

    def test_client_cannot_supply_results_or_verified_flags(self):
        for name, value in [('result', 'ACCEPTED'), ('quoteVerified', True), ('checks', self.result['checks']), ('policyVersion', 'trusted')]:
            payload = copy.deepcopy(self.request)
            payload[name] = value
            self.invalid(payload)

    def test_missing_fields_and_wrong_versions_fail(self):
        for original in (self.request, self.result):
            for key in original:
                if key == 'kind':
                    continue
                payload = copy.deepcopy(original)
                del payload[key]
                self.invalid(payload)
            payload = copy.deepcopy(original)
            payload['schemaVersion'] = 1
            self.invalid(payload)

    def test_nonce_and_binary_encoding_limits(self):
        for nonce in ['', 'ab', 'z'*64, '0'*65, '0'*64+'\n']:
            payload = copy.deepcopy(self.request)
            payload['nonce'] = nonce
            self.invalid(payload)
        for value in ['1', 'zz', '00'*8193, '00\n']:
            payload = copy.deepcopy(self.request)
            payload['quote'] = {'format':'tpms-attest-tpmt-signature-hex', 'attest':value, 'signature':'00'}
            self.invalid(payload)

    def test_structurally_valid_quote_is_not_a_verified_quote(self):
        payload = copy.deepcopy(self.request)
        payload['quote'] = {'format':'tpms-attest-tpmt-signature-hex', 'attest':'00', 'signature':'00'}
        self.validators[payload['kind']].validate(payload)
        payload['quote']['quoteVerified'] = True
        self.invalid(payload)

    def test_pcr_bounds_and_log_limits(self):
        payload = copy.deepcopy(self.request)
        payload['measurements'] = {'bank':'sha256', 'pcrs':[{'index':10, 'digest':'00'*32}], 'bootLog':None, 'imaLog':None}
        self.validators[payload['kind']].validate(payload)
        for index in [-1, 24, True]:
            bad = copy.deepcopy(payload)
            bad['measurements']['pcrs'][0]['index'] = index
            self.invalid(bad)
        payload['measurements']['imaLog'] = '00'*1048577
        self.invalid(payload)

    def test_acceptance_requires_every_server_check(self):
        payload = copy.deepcopy(self.result)
        payload['result'] = 'ACCEPTED'
        self.invalid(payload)
        payload['checks'] = {key:'VERIFIED' for key in payload['checks']}
        payload['reasons'] = ['SYNTHETIC_POLICY_SATISFIED']
        self.validators[payload['kind']].validate(payload)
        for key in payload['checks']:
            for state in ['FAILED', 'UNAVAILABLE', 'NOT_CHECKED']:
                bad = copy.deepcopy(payload)
                bad['checks'][key] = state
                self.invalid(bad)

    def test_failed_check_requires_rejection(self):
        for key in self.result['checks']:
            payload = copy.deepcopy(self.result)
            payload['checks'][key] = 'FAILED'
            self.invalid(payload)
            payload['result'] = 'REJECTED'
            self.validators[payload['kind']].validate(payload)

    def test_result_cannot_be_submitted_as_client_evidence(self):
        self.assertTrue(list(self.validators['evidence-submission'].iter_errors(self.result)))
