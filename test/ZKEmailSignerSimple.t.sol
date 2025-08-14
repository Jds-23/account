// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Base.t.sol";
import {ZKEmailSigner} from "../src/ZKEmailSigner.sol";
import {ERC1967Factory} from "solady/utils/ERC1967Factory.sol";
import {UserOverrideableDKIMRegistry} from "@zk-email/contracts/UserOverrideableDKIMRegistry.sol";
import {MockGroth16Verifier} from "./utils/mocks/MockGroth16Verifier.sol";
import {
    EmailAuth,
    EmailAuthMsg,
    EmailProof
} from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import {ERC1967Proxy} from "lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract ZKEmailSignerSimpleTest is BaseTest {
    ZKEmailSigner public zkEmailSigner;
    UserOverrideableDKIMRegistry public dkimRegistry;
    MockGroth16Verifier public verifier;
    EmailAuth public emailAuthImpl;
    ERC1967Factory public factory;

    DelegatedEOA public testAccount;
    address[] public guardians;
    bytes32[] public accountSalts;
    uint256 public constant RECOVERY_DELAY = 1 days;
    uint256 public constant RECOVERY_EXPIRY = 7 days;
    uint256 public constant MINIMUM_DELAY = 12 hours;
    uint8 public constant THRESHOLD = 2;
    bytes32 public recoveryDataHash;
    uint256 public nullifierCount;

    function setUp() public override {
        super.setUp();

        // Deploy ZK Email infrastructure
        _deployInfrastructure();

        // Deploy ZKEmailSigner
        _deployZKEmailSigner();

        // Set up test account
        _setupTestAccount();

        // Set up recovery data
        _setupRecoveryData();
    }

    function _deployInfrastructure() internal {
        address deployer = vm.addr(1);

        vm.startPrank(deployer);

        // Deploy DKIM registry
        UserOverrideableDKIMRegistry dkimImpl = new UserOverrideableDKIMRegistry();
        dkimRegistry = UserOverrideableDKIMRegistry(
            address(
                new ERC1967Proxy(
                    address(dkimImpl), abi.encodeCall(dkimImpl.initialize, (deployer, deployer, 0))
                )
            )
        );

        bytes32 publicKeyHash = 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;
        dkimRegistry.setDKIMPublicKeyHash("gmail.com", publicKeyHash, deployer, new bytes(0));

        verifier = new MockGroth16Verifier();
        emailAuthImpl = new EmailAuth();
        factory = new ERC1967Factory();

        vm.stopPrank();
    }

    function _deployZKEmailSigner() internal {
        zkEmailSigner = new ZKEmailSigner(
            address(verifier),
            address(dkimRegistry),
            address(emailAuthImpl),
            address(0), // No command handler needed for simple test
            uint128(MINIMUM_DELAY),
            address(factory)
        );
    }

    function _setupTestAccount() internal {
        testAccount = _randomEIP7702DelegatedEOA();
        vm.deal(testAccount.eoa, 10 ether);

        // Set up guardians
        accountSalts = new bytes32[](3);
        accountSalts[0] = keccak256("guardian1");
        accountSalts[1] = keccak256("guardian2");
        accountSalts[2] = keccak256("guardian3");

        guardians = new address[](3);
        guardians[0] = zkEmailSigner.computeEmailAuthAddress(testAccount.eoa, accountSalts[0]);
        guardians[1] = zkEmailSigner.computeEmailAuthAddress(testAccount.eoa, accountSalts[1]);
        guardians[2] = zkEmailSigner.computeEmailAuthAddress(testAccount.eoa, accountSalts[2]);
    }

    function _setupRecoveryData() internal {
        // Create a simple recovery data hash for testing
        recoveryDataHash = keccak256(abi.encodePacked(testAccount.eoa, "recovery_operation"));
    }

    // Test the core signature validation functionality
    function testIsValidSignatureWithKeyHashNotConfigured() public {
        // Should fail when no recovery is configured
        bytes4 result = zkEmailSigner.isValidSignatureWithKeyHash(recoveryDataHash, bytes32(0), "");

        assertEq(result, bytes4(0xffffffff)); // _FAIL_VALUE
    }

    // Test with mock recovery setup
    function testIsValidSignatureWithKeyHashSimple() public {
        // This is a simplified test that directly tests the signature validation
        // without going through the full recovery flow

        // For now, just test that the function exists and returns the expected failure
        // when no recovery is in progress
        bytes4 result = zkEmailSigner.isValidSignatureWithKeyHash(recoveryDataHash, bytes32(0), "");

        // Should return _FAIL_VALUE since no recovery is set up
        assertEq(result, bytes4(0xffffffff));
    }

    // Test that the signer was deployed correctly
    function testZKEmailSignerDeployment() public {
        assertTrue(address(zkEmailSigner) != address(0));
        assertEq(zkEmailSigner.verifier(), address(verifier));
        assertEq(zkEmailSigner.dkim(), address(dkimRegistry));
        assertEq(zkEmailSigner.emailAuthImplementation(), address(emailAuthImpl));
        assertEq(zkEmailSigner.minimumDelay(), MINIMUM_DELAY);
    }

    // Test that account activation check works
    function testIsActivated() public {
        // Should return false for unactivated account
        assertFalse(zkEmailSigner.isActivated(testAccount.eoa));
    }
}
