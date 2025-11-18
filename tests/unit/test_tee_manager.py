#!/usr/bin/env python3
"""
Unit tests for TEE Manager

Tests cover:
- TEE mode configuration
- Keypair generation (baseline and TEE-derived)
- Attestation generation and verification
- Statistics tracking
- Error handling
- Graceful degradation when TEE unavailable
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

import unittest
from unittest.mock import Mock, patch, MagicMock
from tee_manager import (
    TEEManager,
    TEEMode,
    TEEKeyPair,
    AttestationReport,
    get_tee_manager,
    set_tee_mode,
    TEE_AVAILABLE
)
from py_ecc.bls import G2ProofOfPossession as bls


# Sample TDX quote for testing attestation verification
# Replace this with a real TDX quote from your environment
SAMPLE_TDX_QUOTE = "040002008100000000000000939a7233f79c4ca9940a0db3957f0607c737391927421f57fb8a2f5f6d9f759600000000060103000000000000000000000000005b38e33a6487958b72c3c12a938eaa5e3fd4510c51aeeab58c7d5ecee41d7c436489d6c8e4f92f160b7cad34207b00c100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000e702060000000000c68518a0ebb42136c12b2275164f8c72f25fa9a34392228687ed6e9caeb9c0f1dbd895e9cf475121c029dc47e70e91fd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000079207fa707c5bbf697d579bbd44c2ba14f8565d528aff0de407c58fd34815b67a35cfbb0a0d996b1c7b911a2c8ae806c154e08f5c1f7b1fce4cbfe1c14f3ba67b70044ede2751487279cd1f2e4239dee99a6d45e24ebde6b6a6f5ae49878e0e69edcd363660e85b71c318324996dda756c372d9f6960edbfa863b1e684822eb48dd95e218ae2b78e51ef97f3b8f5c9dcfd7145f6cfd6ace363058e697a9542ddb7eb86d30a1f4d01a84136b00f12ade3fd63cbc69722c0f2d3e2e209a46edfdc16d0790c1181a43490d3f40ada9eda87c3283e22c6b233456c1f70cfd30c3152cc80db5d45dd72ce0d5a03a5a2a07deba7730b24ea556c8412c68efd695a4174cc1000003a6d229e468dbf83f2f46b04953dfadf65c35916b663c16e7156021c6e6290ca2a03e167bbef1f8c0395584d09efcd4b978e2f7a486bd35c76635be4115f37312f700bfda2a449d6089c2d6c2ace9587ecc6caa2f5b08aa7239f0b00c07d00e84d38a0867754b8269294ef70f9e481512d9b2da65b70f7cafacd1e4dcd333b900600461000000303191b04ff0006000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000e700000000000000e5a3a7b5d830c2953b98534c6c59a3a34fdc34e933f7f5898f0a85cf08846bca0000000000000000000000000000000000000000000000000000000000000000dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002e0c701cd6b96889f400f042785cd2a1427dd7adeac1e8887b3a2347ac90d29800000000000000000000000000000000000000000000000000000000000000007318a3eb583e75173e453e0e6b0a458d8dcfd34d671d4cfe29f15cdb1597c99521df4b5b2700fd94d0048ce14906d87cdde21480440e6c1ece84ab0b5b4765192000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f05005e0e00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d49494538544343424a65674177494241674956414b6d477058726d2f612f777a7a696a58585a71397a67647773356d4d416f4743437147534d343942414d430a4d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d0a45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155450a4341774351304578437a414a42674e5642415954416c56544d423458445449314d446b774d54417a4e4449784d316f5844544d794d446b774d54417a4e4449780a4d316f77634445694d434147413155454177775a535735305a5777675530645949464244537942445a584a3061575a70593246305a5445614d426747413155450a43677752535735305a577767513239796347397959585270623234784644415342674e564241634d43314e68626e526849454e7359584a684d517377435159440a5651514944414a445154454c4d416b474131554542684d4356564d775754415442676371686b6a4f5051494242676771686b6a4f50514d4242774e43414152380a424f6c71566330583955544f4870753564485379666e72626f7a6333384c4b67767a65714c304b7a453850543275736b7a5a687a4662726e56424d34693347610a672f59694d344f76502f4e5874446966684430776f3449444444434341776777487759445652306a42426777466f41556c5739647a62306234656c4153636e550a3944504f4156634c336c5177617759445652306642475177596a42676f46366758495a616148523063484d364c79396863476b7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253397a5a3367765932567964476c6d61574e6864476c76626939324e4339775932746a636d772f593245390a6347786864475a76636d306d5a57356a62325270626d63395a4756794d42304741315564446751574242524b6c6961753558376f657a7149707a344c6e4577380a2b4a64646654414f42674e56485138424166384542414d434273417744415944565230544151482f4241497741444343416a6b4743537147534962345451454e0a4151534341696f776767496d4d42344743697147534962345451454e41514545454c2b4c3658697564636b2f68693465612b53426a746b776767466a42676f710a686b69472b453042445145434d494942557a415142677371686b69472b4530424451454341514942417a415142677371686b69472b45304244514543416749420a417a415142677371686b69472b4530424451454341774942416a415142677371686b69472b4530424451454342414942416a415142677371686b69472b4530420a44514543425149424244415142677371686b69472b45304244514543426749424154415142677371686b69472b453042445145434277494241444151426773710a686b69472b45304244514543434149424254415142677371686b69472b45304244514543435149424144415142677371686b69472b45304244514543436749420a4144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69472b4530420a44514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b453042445145434477494241444151426773710a686b69472b45304244514543454149424144415142677371686b69472b4530424451454345514942437a416642677371686b69472b45304244514543456751510a41774d43416751424141554141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b453042445145450a4241617777473841414141774477594b4b6f5a496876684e4151304242516f424154416542676f71686b69472b453042445145474242412b36397741464b53710a7962304f7033714e397938454d45514743697147534962345451454e415163774e6a415142677371686b69472b45304244514548415145422f7a4151426773710a686b69472b45304244514548416745422f7a415142677371686b69472b45304244514548417745422f7a414b42676771686b6a4f5051514441674e49414442460a41694541774d6857456c6f664d4e34786b2b4d5862465133586d55583056745a44384e5647547830775a54716375494349473265534a475774323248394975500a6e46675377326357396245682b506f6a563452494c583861354277440a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436c6a4343416a32674177494241674956414a567658633239472b487051456e4a3150517a7a674658433935554d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484178496a41670a42674e5642414d4d47556c756447567349464e4857434251513073675547786864475a76636d306751304578476a415942674e5642416f4d45556c75644756730a49454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b474131554543417743513045780a437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741454e53422f377432316c58534f0a3243757a7078773734654a423732457944476757357258437478327456544c7136684b6b367a2b5569525a436e71523770734f766771466553786c6d546c4a6c0a65546d693257597a33714f42757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f536347724442530a42674e5648523845537a424a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b633256790a646d6c6a5a584d75615735305a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e5648513445466751556c5739640a7a62306234656c4153636e553944504f4156634c336c517744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159420a4166384341514177436759494b6f5a497a6a30454177494452774177524149675873566b6930772b6936565947573355462f32327561586530594a446a3155650a6e412b546a44316169356343494359623153416d4435786b66545670766f34556f79695359787244574c6d5552344349394e4b7966504e2b0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"  # TODO: Paste real TDX quote here


class TestTEEMode(unittest.TestCase):
    """Test TEE mode enumeration"""

    def test_modes_exist(self):
        """Test that all modes are defined"""
        self.assertEqual(TEEMode.DISABLED.value, "disabled")
        self.assertEqual(TEEMode.ENABLED.value, "enabled")
        self.assertEqual(TEEMode.BENCHMARK.value, "benchmark")


class TestTEEManagerBaseline(unittest.TestCase):
    """Test TEE Manager in baseline mode (no TEE required)"""

    def setUp(self):
        """Initialize manager in disabled mode"""
        self.manager = TEEManager(mode=TEEMode.DISABLED)

    def test_initialization(self):
        """Test manager initializes correctly"""
        self.assertEqual(self.manager.mode, TEEMode.DISABLED)
        self.assertIsNotNone(self.manager.stats)
        self.assertEqual(self.manager.stats['key_generations'], 0)

    def test_generate_baseline_keypair(self):
        """Test baseline BLS keypair generation"""
        keypair = self.manager.generate_keypair(tee_enabled=False)

        # Verify keypair structure
        self.assertIsInstance(keypair, TEEKeyPair)
        self.assertEqual(len(keypair.private_key), 32)
        self.assertEqual(len(keypair.public_key), 48)
        self.assertFalse(keypair.tee_derived)
        self.assertIsNotNone(keypair.derivation_time_ms)
        self.assertGreater(keypair.derivation_time_ms, 0)

    def test_keypair_is_valid_bls(self):
        """Test that generated keypair is valid BLS12-381"""
        keypair = self.manager.generate_keypair(tee_enabled=False)

        # Verify public key matches private key
        sk_int = int.from_bytes(keypair.private_key, 'big')
        expected_pk = bls.SkToPk(sk_int)

        # bls.SkToPk returns bytes directly (48 bytes for BLS12-381)
        self.assertEqual(keypair.public_key, expected_pk)

    def test_keypair_uniqueness(self):
        """Test that each keypair is unique"""
        keypair1 = self.manager.generate_keypair(tee_enabled=False)
        keypair2 = self.manager.generate_keypair(tee_enabled=False)

        self.assertNotEqual(keypair1.private_key, keypair2.private_key)
        self.assertNotEqual(keypair1.public_key, keypair2.public_key)

    def test_statistics_tracking(self):
        """Test that statistics are tracked correctly"""
        # Initial state
        self.assertEqual(self.manager.stats['key_generations'], 0)

        # Generate keypairs
        keypair1 = self.manager.generate_keypair(tee_enabled=False)
        self.assertEqual(self.manager.stats['key_generations'], 1)

        keypair2 = self.manager.generate_keypair(tee_enabled=False)
        self.assertEqual(self.manager.stats['key_generations'], 2)

        # Verify total time is sum of individual times
        expected_total = keypair1.derivation_time_ms + keypair2.derivation_time_ms
        self.assertAlmostEqual(
            self.manager.stats['total_key_gen_time_ms'],
            expected_total,
            delta=0.001
        )

    def test_get_statistics(self):
        """Test statistics retrieval"""
        # Generate some keypairs
        for _ in range(5):
            self.manager.generate_keypair(tee_enabled=False)

        stats = self.manager.get_statistics()

        self.assertEqual(stats['key_generations'], 5)
        self.assertGreater(stats['avg_key_gen_time_ms'], 0)
        self.assertEqual(stats['attestations_generated'], 0)
        self.assertEqual(stats['avg_attestation_time_ms'], 0)

    def test_reset_statistics(self):
        """Test statistics reset"""
        # Generate some data
        self.manager.generate_keypair(tee_enabled=False)
        self.assertEqual(self.manager.stats['key_generations'], 1)

        # Reset
        self.manager.reset_statistics()

        # Verify reset
        self.assertEqual(self.manager.stats['key_generations'], 0)
        self.assertEqual(self.manager.stats['total_key_gen_time_ms'], 0)

    def test_tee_mode_disabled_prevents_tee_ops(self):
        """Test that TEE operations fail when mode is DISABLED"""
        with self.assertRaises(RuntimeError):
            self.manager.generate_keypair(tee_enabled=True)


@unittest.skipIf(not TEE_AVAILABLE, "TEE SDK not available")
class TestTEEManagerWithTEE(unittest.TestCase):
    """Test TEE Manager with TEE enabled (requires dstack_sdk)"""

    def setUp(self):
        """Initialize manager in enabled mode"""
        self.manager = TEEManager(mode=TEEMode.ENABLED)

    def test_tee_keypair_generation(self):
        """Test TEE-derived keypair generation"""
        keypair = self.manager.generate_keypair(tee_enabled=True)

        # Verify keypair structure
        self.assertIsInstance(keypair, TEEKeyPair)
        self.assertEqual(len(keypair.private_key), 32)
        self.assertEqual(len(keypair.public_key), 48)
        self.assertTrue(keypair.tee_derived)
        self.assertGreater(keypair.derivation_time_ms, 0)

    def test_attestation_generation(self):
        """Test TDX attestation generation"""
        payload = "test_user_registration"
        attestation = self.manager.generate_attestation(payload)

        # Verify attestation structure
        self.assertIsInstance(attestation, AttestationReport)
        self.assertIsNotNone(attestation.quote)
        self.assertEqual(attestation.payload, payload)
        self.assertGreater(attestation.generation_time_ms, 0)
        self.assertGreater(attestation.quote_size_bytes, 0)

    def test_attestation_with_large_payload(self):
        """Test attestation with payload > 64 bytes (should hash it)"""
        large_payload = "x" * 1000
        attestation = self.manager.generate_attestation(large_payload)

        # Should succeed despite large payload
        self.assertIsNotNone(attestation.quote)

    def test_attestation_statistics(self):
        """Test attestation statistics tracking"""
        self.assertEqual(self.manager.stats['attestations_generated'], 0)

        attestation = self.manager.generate_attestation("test")
        self.assertEqual(self.manager.stats['attestations_generated'], 1)
        self.assertAlmostEqual(
            self.manager.stats['total_attestation_time_ms'],
            attestation.generation_time_ms,
            delta=0.001
        )

    def test_verify_attestation_requires_dcap_qvl(self):
        """Test attestation verification with a sample TDX quote (ignores payload mismatch)"""

        # Dummy payload
        payload = "dummy_payload_for_testing"
        try:
            is_valid, duration_ms = self.manager.verify_attestation(
                SAMPLE_TDX_QUOTE,
                payload,
                check_payload=False  # Ignore payload mismatch for testing
            )
            # If dcap-qvl is available, verification should complete
            self.assertIsInstance(is_valid, bool)
            self.assertGreater(duration_ms, 0)
            print(f"[TEST] Attestation verification completed: valid={is_valid}, time={duration_ms:.2f}ms")
        except RuntimeError as e:
            # Expected if dcap-qvl is not installed
            self.assertIn("dcap_qvl not available", str(e))
            print("[TEST] dcap-qvl not available - verification skipped (expected)")

    def test_get_ethereum_account(self):
        """Test Ethereum account derivation from TEE"""
        account = self.manager.get_ethereum_account(
            path="test/ethereum/path",
            purpose="testing"
        )

        # Verify account has required attributes
        self.assertIsNotNone(account)
        self.assertIsNotNone(account.address)
        # Account should have Web3.py account interface


class TestTEEManagerMocked(unittest.TestCase):
    """Test TEE Manager with mocked dstack SDK (no hardware required)"""

    @patch('tee_manager.TEE_AVAILABLE', True)
    @patch('tee_manager.DstackClient')
    def test_tee_keypair_with_mock(self, mock_dstack_client):
        """Test TEE keypair generation with mocked SDK"""
        # Setup mock
        mock_key_response = Mock()
        mock_key_response.decode_key.return_value = b'\x42' * 32  # Mock 32-byte key
        mock_dstack_client.return_value.get_key.return_value = mock_key_response

        # Test
        manager = TEEManager(mode=TEEMode.ENABLED)
        keypair = manager.generate_keypair(tee_enabled=True)

        # Verify SDK was called
        mock_dstack_client.return_value.get_key.assert_called_once()
        call_args = mock_dstack_client.return_value.get_key.call_args[0]
        self.assertIn('pbts/bls/', call_args[0])  # Path
        self.assertEqual(call_args[1], 'signature')  # Purpose

        # Verify keypair
        self.assertTrue(keypair.tee_derived)
        self.assertEqual(len(keypair.private_key), 32)

    @patch('tee_manager.TEE_AVAILABLE', True)
    @patch('tee_manager.DstackClient')
    def test_attestation_with_mock(self, mock_dstack_client):
        """Test attestation generation with mocked SDK"""
        # Setup mock
        mock_quote_response = Mock()
        mock_quote_response.quote = b'MOCK_TDX_QUOTE_DATA_' * 50
        mock_dstack_client.return_value.get_quote.return_value = mock_quote_response

        # Test
        manager = TEEManager(mode=TEEMode.ENABLED)
        attestation = manager.generate_attestation("test_payload")

        # Verify SDK was called
        mock_dstack_client.return_value.get_quote.assert_called_once()

        # Verify attestation
        self.assertEqual(attestation.quote, b'MOCK_TDX_QUOTE_DATA_' * 50)
        self.assertEqual(attestation.payload, "test_payload")


class TestTEEManagerSingleton(unittest.TestCase):
    """Test singleton pattern for TEE manager"""

    def setUp(self):
        """Reset singleton before each test"""
        import tee_manager
        tee_manager._tee_manager_instance = None

    def test_get_tee_manager_creates_instance(self):
        """Test that get_tee_manager creates instance"""
        manager = get_tee_manager(TEEMode.DISABLED)
        self.assertIsNotNone(manager)
        self.assertEqual(manager.mode, TEEMode.DISABLED)

    def test_get_tee_manager_returns_same_instance(self):
        """Test that get_tee_manager returns singleton"""
        manager1 = get_tee_manager(TEEMode.DISABLED)
        manager2 = get_tee_manager(TEEMode.BENCHMARK)  # Mode ignored

        self.assertIs(manager1, manager2)

    def test_set_tee_mode_creates_new_instance(self):
        """Test that set_tee_mode creates new instance"""
        manager1 = get_tee_manager(TEEMode.DISABLED)
        set_tee_mode(TEEMode.DISABLED)
        manager2 = get_tee_manager()

        self.assertIsNot(manager1, manager2)


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""

    def test_tee_mode_enabled_without_sdk(self):
        """Test that ENABLED mode fails without SDK"""
        if not TEE_AVAILABLE:
            with self.assertRaises(RuntimeError) as ctx:
                TEEManager(mode=TEEMode.ENABLED)
            self.assertIn("dstack_sdk not available", str(ctx.exception))

    def test_attestation_without_tee(self):
        """Test that attestation fails without TEE"""
        manager = TEEManager(mode=TEEMode.DISABLED)

        with self.assertRaises(RuntimeError) as ctx:
            manager.generate_attestation("test")
        self.assertIn("TEE not available", str(ctx.exception))

    def test_ethereum_account_without_tee(self):
        """Test that Ethereum derivation fails without TEE"""
        manager = TEEManager(mode=TEEMode.DISABLED)

        with self.assertRaises(RuntimeError) as ctx:
            manager.get_ethereum_account()
        self.assertIn("TEE not available", str(ctx.exception))


def run_tests():
    """Run all tests"""
    unittest.main(verbosity=2)


if __name__ == '__main__':
    run_tests()
