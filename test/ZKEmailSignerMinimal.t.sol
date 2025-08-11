// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import {ZKEmailSigner} from "../src/ZKEmailSigner.sol";
import {IthacaAccountRecoveryCommandHandler} from "../src/IthacaAccountRecoveryCommandHandler.sol";
import {ERC1967Factory} from "solady/utils/ERC1967Factory.sol";

contract MockVerifier {
    function verifyEmailAuthProof(bytes calldata, bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}

contract MockDKIM {
    function isDKIMPublicKeyHashValid(string calldata, bytes32) external pure returns (bool) {
        return true;
    }
}

contract MockEmailAuth {
    function initialize(address, bytes32, uint256) external {}
    function controller() external pure returns (address) {
        return address(0);
    }
}

contract ZKEmailSignerMinimalTest is Test {
    ZKEmailSigner public zkEmailSigner;
    IthacaAccountRecoveryCommandHandler public commandHandler;
    
    function setUp() public {
        // Deploy minimal mocks
        MockVerifier verifier = new MockVerifier();
        MockDKIM dkim = new MockDKIM();
        MockEmailAuth emailAuth = new MockEmailAuth();
        ERC1967Factory factory = new ERC1967Factory();
        
        // Deploy ZKEmailSigner first (with placeholder command handler)
        zkEmailSigner = new ZKEmailSigner(
            address(verifier),
            address(dkim),
            address(emailAuth),
            address(0x1234), // placeholder
            12 hours,
            address(factory)
        );
        
        // Deploy command handler
        commandHandler = new IthacaAccountRecoveryCommandHandler(address(zkEmailSigner));
    }

    function testBasicFunctionality() public {
        // Test that the contract was deployed
        assertTrue(address(zkEmailSigner) != address(0));
    }

    function testIsValidSignatureWithKeyHashNoRecovery() public {
        // Test signature validation with no recovery in progress
        bytes32 someDigest = keccak256("test");
        
        // Should revert with RecoveryNotInProgress when no recovery is configured
        vm.expectRevert(abi.encodeWithSignature("RecoveryNotInProgress()"));
        zkEmailSigner.isValidSignatureWithKeyHash(
            someDigest,
            bytes32(0),
            ""
        );
    }

    function testIsActivated() public {
        // Test account activation check
        address testAccount = address(0x123);
        
        // Should return false for unactivated account
        assertFalse(zkEmailSigner.isActivated(testAccount));
    }

    function testCommandHandlerIntegration() public {
        // Test that command handler functions work
        string[][] memory acceptanceTemplates = commandHandler.acceptanceCommandTemplates();
        assertTrue(acceptanceTemplates.length > 0);
        
        string[][] memory recoveryTemplates = commandHandler.recoveryCommandTemplates();
        assertTrue(recoveryTemplates.length > 0);
    }
}