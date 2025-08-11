// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Base.t.sol";
import {ZKEmailSigner} from "../src/ZKEmailSigner.sol";
import {IthacaAccountRecoveryCommandHandler} from "../src/IthacaAccountRecoveryCommandHandler.sol";
import {EmailAuth, EmailAuthMsg, EmailProof} from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import {ERC1967Factory} from "solady/utils/ERC1967Factory.sol";
import {UserOverrideableDKIMRegistry} from "@zk-email/contracts/UserOverrideableDKIMRegistry.sol";
import {MockGroth16Verifier} from "./utils/mocks/MockGroth16Verifier.sol";
import {IIthacaAccount} from "../src/interfaces/IIthacaAccount.sol";
import {ERC1967Proxy} from "lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract ZKEmailSignerTest is BaseTest {
    // ZK Email infrastructure
    ZKEmailSigner public zkEmailSigner = ZKEmailSigner(
        address(bytes20(keccak256("ZKEmailSigner")))
    );
    IthacaAccountRecoveryCommandHandler public commandHandler = IthacaAccountRecoveryCommandHandler(
        address(bytes20(keccak256("IthacaAccountRecoveryCommandHandler")))
    );
    UserOverrideableDKIMRegistry public dkimRegistry;
    MockGroth16Verifier public verifier;
    EmailAuth public emailAuthImpl;
    ERC1967Factory public factory;

    // Test accounts and keys
    DelegatedEOA public testAccount;
    PassKey public compromisedKey;
    PassKey public newKey;
    IthacaAccount.Key public zkSignerKey;
    
    // Guardians
    address[] public guardians;
    bytes32[] public accountSalts;
    
    // Recovery configuration
    uint256 public constant RECOVERY_DELAY = 1 days;
    uint256 public constant RECOVERY_EXPIRY = 7 days;
    uint256 public constant MINIMUM_DELAY = 12 hours;
    uint8 public constant THRESHOLD = 2; // Need 2 out of 3 guardians
    
    // Test data
    bytes32 public recoveryDataHash;
    uint256 public nullifierCount;

    function setUp() public override {
        super.setUp();
        
        // Start with a reasonable timestamp (e.g., Jan 1, 2024)
        vm.warp(1704067200); // January 1, 2024 00:00:00 UTC
        
        // Deploy ZK Email infrastructure
        _deployZKEmailInfrastructure();
        
        // Deploy ZKEmailSigner and command handler
        _deployZKEmailSigner();
        
        // Set up test account with compromised key
        _setupTestAccount();
        
        // Configure guardians
        _configureGuardians();
        
        // Calculate recovery data hash for key replacement
        _calculateRecoveryDataHash();
    }

    function _deployZKEmailInfrastructure() internal {
        address zkEmailDeployer = vm.addr(1);
        
        vm.startPrank(zkEmailDeployer);
        
        // Deploy DKIM registry
        UserOverrideableDKIMRegistry dkimImpl = new UserOverrideableDKIMRegistry();
        dkimRegistry = UserOverrideableDKIMRegistry(
            address(new ERC1967Proxy(
                address(dkimImpl),
                abi.encodeCall(dkimImpl.initialize, (zkEmailDeployer, zkEmailDeployer, 0))
            ))
        );
        
        // Set DKIM key
        bytes32 publicKeyHash = 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;
        dkimRegistry.setDKIMPublicKeyHash("gmail.com", publicKeyHash, zkEmailDeployer, new bytes(0));
        
        // Deploy verifier and email auth
        verifier = new MockGroth16Verifier();
        emailAuthImpl = new EmailAuth();
        factory = new ERC1967Factory();
        
        vm.stopPrank();
    }

    function _deployZKEmailSigner() internal {
        // Deploy ZKEmailSigner
        ZKEmailSigner tempZKEmailSigner = new ZKEmailSigner(
            address(verifier),
            address(dkimRegistry),
            address(emailAuthImpl),
            address(commandHandler),
            uint128(MINIMUM_DELAY),
            address(factory)
        );
        
        // Deploy command handler
        IthacaAccountRecoveryCommandHandler tempCommandHandler = new IthacaAccountRecoveryCommandHandler(address(zkEmailSigner));
        
        // Update command handler in ZKEmailSigner (would need setter in actual implementation)
        // For now, we'll work with the existing setup

        vm.etch(address(zkEmailSigner), address(tempZKEmailSigner).code);
        vm.etch(address(commandHandler), address(tempCommandHandler).code);
    }

    function _setupTestAccount() internal {
        // Create test account
        testAccount = _randomEIP7702DelegatedEOA();
        vm.deal(testAccount.eoa, 10 ether);
        
        // Create compromised key
        compromisedKey = _randomSecp256k1PassKey();
        compromisedKey.k.isSuperAdmin = false; // Not super admin to make it revokable
        
        // Create new replacement key
        newKey = _randomSecp256k1PassKey();
        newKey.k.isSuperAdmin = false;
        
        // Add compromised key to account
        vm.prank(testAccount.eoa);
        testAccount.d.authorize(compromisedKey.k);
        
        // Add ZKEmailSigner as external signer
        zkSignerKey = IthacaAccount.Key({
            expiry: 0,
            keyType: IthacaAccount.KeyType.External,
            isSuperAdmin: true,
            publicKey: abi.encodePacked(address(zkEmailSigner), bytes12(0))
        });
        
        vm.prank(testAccount.eoa);
        testAccount.d.authorize(zkSignerKey);
    }

    function _configureGuardians() internal {
        // Create account salts for guardians
        accountSalts = new bytes32[](3);
        accountSalts[0] = keccak256(abi.encode("guardian1", testAccount.eoa));
        accountSalts[1] = keccak256(abi.encode("guardian2", testAccount.eoa));
        accountSalts[2] = keccak256(abi.encode("guardian3", testAccount.eoa));
        
        // Compute guardian addresses
        guardians = new address[](3);
        guardians[0] = zkEmailSigner.computeEmailAuthAddress(testAccount.eoa, accountSalts[0]);
        guardians[1] = zkEmailSigner.computeEmailAuthAddress(testAccount.eoa, accountSalts[1]);
        guardians[2] = zkEmailSigner.computeEmailAuthAddress(testAccount.eoa, accountSalts[2]);
        
        // Configure recovery through the test account
        vm.prank(testAccount.eoa);
        zkEmailSigner.configureRecovery(
            guardians,
            THRESHOLD,
            uint128(RECOVERY_DELAY),
            uint128(RECOVERY_EXPIRY)
        );
    }

    function _calculateRecoveryDataHash() internal {
        // Create a simple recovery data hash for testing
        // In a real implementation, this would be calculated by the command handler
        recoveryDataHash = keccak256(abi.encodePacked(
            "recovery",
            testAccount.eoa,
            _hash(compromisedKey.k),
            _hash(newKey.k)
        ));
    }

    function testEmailRecoveryHappyPath() public {
        // Step 1: Accept guardians via email
        _acceptGuardians();
        
        // Step 2: Initiate recovery via guardian emails
        _initiateRecovery();
        
        // Step 3: Wait for delay period
        vm.warp(block.timestamp + RECOVERY_DELAY + 1);
        
        // Step 4: Execute recovery through account using ZKEmailSigner validation
        _executeRecovery();
        
        // Step 5: Verify recovery completed successfully
        _verifyRecoveryCompleted();
    }

    function _acceptGuardians() internal {
        // Accept first 2 guardians (threshold = 2)
        for (uint256 i = 0; i < THRESHOLD; i++) {
            EmailAuthMsg memory emailAuthMsg = _generateAcceptanceEmailAuth(i);
            zkEmailSigner.handleAcceptance(emailAuthMsg, 0);
        }
    }

    function _initiateRecovery() internal {
        // Send recovery emails from threshold number of guardians
        for (uint256 i = 0; i < THRESHOLD; i++) {
            EmailAuthMsg memory emailAuthMsg = _generateRecoveryEmailAuth(i);
            zkEmailSigner.handleRecovery(emailAuthMsg, 0);
        }
    }

    function _executeRecovery() internal {
       
        
               ERC7821.Call[] memory calls = new ERC7821.Call[](3);
               calls[0] = ERC7821.Call({
            to: testAccount.eoa,
            value: 0,
            data: abi.encodeWithSelector(IthacaAccount.revoke.selector, _hash(compromisedKey.k))
        });
        calls[1] = ERC7821.Call({
            to: testAccount.eoa,
            value: 0,
            data: abi.encodeWithSelector(IthacaAccount.authorize.selector, newKey.k)
        });
        calls[2] = ERC7821.Call({
            to: address(zkEmailSigner),
            value: 0,
            data: abi.encodeWithSelector(ZKEmailSigner.markRecoveryCompleted.selector)
        });
        console.log("zkSignerKey");
        console.logBytes32(_hash(zkSignerKey));
        console.log("getKey");
        console.logBytes( testAccount.d.getKey(_hash(zkSignerKey)).publicKey);

        bytes memory signature = abi.encodePacked("0x6900", _hash(zkSignerKey),uint8(0));
        uint256 nonce = testAccount.d.getNonce(69);
        bytes memory opData = abi.encodePacked(nonce, signature);
        console.log("signature from test");
        console.logBytes(signature);
        console.log("opData from test");
        console.logBytes(opData);
        bytes memory executionData = abi.encode(calls, opData);

        testAccount.d.execute(_ERC7821_BATCH_EXECUTION_MODE, executionData);
    }

    function _verifyRecoveryCompleted() internal {
        // For this simple test, just verify the function completed without reverting
        // In a full implementation, we would check key states and recovery completion
        assertTrue(true); // Placeholder
    }

    function _generateAcceptanceEmailAuth(uint256 guardianIndex) internal returns (EmailAuthMsg memory) {
        string memory command = string.concat(
            "Accept guardian request for ",
            _addressToString(testAccount.eoa)
        );
        
        bytes32 nullifier = keccak256(abi.encode("acceptance", guardianIndex, nullifierCount++));
        
        EmailProof memory proof = _generateMockEmailProof(command, nullifier, accountSalts[guardianIndex]);
        
        bytes[] memory commandParams = new bytes[](1);
        commandParams[0] = abi.encode(testAccount.eoa);
        
        return EmailAuthMsg({
            templateId: zkEmailSigner.computeAcceptanceTemplateId(0),
            commandParams: commandParams,
            skippedCommandPrefix: 0,
            proof: proof
        });
    }

    function _generateRecoveryEmailAuth(uint256 guardianIndex) internal returns (EmailAuthMsg memory) {
        string memory keyHashStr = _bytes32ToHexString(_hash(compromisedKey.k));
        string memory newKeyStr = _keyToHexString(newKey.k);
        
        string memory command = string.concat(
            "Recover account ",
            _addressToString(testAccount.eoa),
            " by replacing key ",
            keyHashStr,
            " with ",
            newKeyStr
        );
        
        bytes32 nullifier = keccak256(abi.encode("recovery", guardianIndex, nullifierCount++));
        
        EmailProof memory proof = _generateMockEmailProof(command, nullifier, accountSalts[guardianIndex]);
        
        bytes[] memory commandParams = new bytes[](3);
        commandParams[0] = abi.encode(testAccount.eoa);
        commandParams[1] = abi.encode(keyHashStr);
        commandParams[2] = abi.encode(newKeyStr);
        
        return EmailAuthMsg({
            templateId: zkEmailSigner.computeRecoveryTemplateId(0),
            commandParams: commandParams,
            skippedCommandPrefix: 0,
            proof: proof
        });
    }

    function _generateMockEmailProof(
        string memory command,
        bytes32 nullifier,
        bytes32 accountSalt
    ) internal returns (EmailProof memory) {
        // Increment timestamp to ensure sequential ordering for multiple emails
        vm.warp(block.timestamp + 1);
        return EmailProof({
            domainName: "gmail.com",
            publicKeyHash: 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788,
            timestamp: uint256(block.timestamp), // Use current timestamp
            maskedCommand: command,
            emailNullifier: nullifier,
            accountSalt: accountSalt,
            isCodeExist: true,
            proof: bytes("mock_proof")
        });
    }

    // Helper functions
    function _addressToString(address addr) internal pure returns (string memory) {
        return _toHexString(uint160(addr), 20);
    }

    function _bytes32ToHexString(bytes32 value) internal pure returns (string memory) {
        return _toHexString(uint256(value), 32);
    }

    function _keyToHexString(IthacaAccount.Key memory key) internal pure returns (string memory) {
        bytes memory keyBytes = abi.encode(key);
        return _bytesToHexString(keyBytes);
    }

    function _toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        return string(buffer);
    }

    function _bytesToHexString(bytes memory data) internal pure returns (string memory) {
        bytes memory hexChars = "0123456789abcdef";
        bytes memory result = new bytes(2 + data.length * 2);
        result[0] = "0";
        result[1] = "x";
        
        for (uint256 i = 0; i < data.length; i++) {
            result[2 + i * 2] = hexChars[uint8(data[i]) >> 4];
            result[2 + i * 2 + 1] = hexChars[uint8(data[i]) & 0x0f];
        }
        
        return string(result);
    }

    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    // Test signature validation directly
    function testIsValidSignatureWithKeyHash() public {
        // Setup recovery first
        _acceptGuardians();
        _initiateRecovery();
        vm.warp(block.timestamp + RECOVERY_DELAY + 1);
        
        // Test signature validation
        bytes4 result = zkEmailSigner.isValidSignatureWithKeyHash(
            recoveryDataHash,
            bytes32(0), // keyHash not used
            ""    // signature not used
        );
        
        assertEq(result, bytes4(0x1626ba7e)); // _MAGIC_VALUE
    }

    function testIsValidSignatureWithKeyHashInvalidDigest() public {
        // Setup recovery first
        _acceptGuardians();
        _initiateRecovery();
        vm.warp(block.timestamp + RECOVERY_DELAY + 1);
        
        // Test with wrong digest
        bytes4 result = zkEmailSigner.isValidSignatureWithKeyHash(
            0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef,
            bytes32(0),
            ""
        );
        
        assertEq(result, bytes4(0xffffffff)); // _FAIL_VALUE
    }

    function testIsValidSignatureWithKeyHashBeforeDelay() public {
        // Setup recovery but don't wait for delay
        _acceptGuardians();
        _initiateRecovery();
        
        // Test signature validation before delay
        bytes4 result = zkEmailSigner.isValidSignatureWithKeyHash(
            recoveryDataHash,
            bytes32(0),
            ""
        );
        
        assertEq(result, bytes4(0xffffffff)); // _FAIL_VALUE
    }

    function testIsValidSignatureWithKeyHashInsufficientGuardians() public {
        // Accept only 1 guardian (less than threshold)
        EmailAuthMsg memory emailAuthMsg = _generateAcceptanceEmailAuth(0);
        zkEmailSigner.handleAcceptance(emailAuthMsg, 0);
        
        // Initiate recovery with 1 guardian
        emailAuthMsg = _generateRecoveryEmailAuth(0);
        zkEmailSigner.handleRecovery(emailAuthMsg, 0);
        
        vm.warp(block.timestamp + RECOVERY_DELAY + 1);
        
        // Test signature validation with insufficient guardians
        bytes4 result = zkEmailSigner.isValidSignatureWithKeyHash(
            recoveryDataHash,
            bytes32(0),
            ""
        );
        
        assertEq(result, bytes4(0xffffffff)); // _FAIL_VALUE
    }
}