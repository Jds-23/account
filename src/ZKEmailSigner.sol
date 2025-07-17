// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IIthacaAccount} from "./interfaces/IIthacaAccount.sol";
import {ISigner} from "./interfaces/ISigner.sol";
import {EmailRecoveryManager} from "./EmailRecoveryManager.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";

/// @title ZKEmailSigner
/// @notice A Signer contract, that extends ZK-email functionality to the Porto Account.
abstract contract ZKEmailSigner is ISigner, EmailRecoveryManager {
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    ////////////////////////////////////////////////////////////////////////
    // Constants
    ////////////////////////////////////////////////////////////////////////

    /// @dev The magic value returned by `isValidSignatureWithKeyHash` when the signature is valid.
    bytes4 internal constant _MAGIC_VALUE = 0x1626ba7e;

    /// @dev The magic value returned by `isValidSignatureWithKeyHash` when the signature is invalid.
    bytes4 internal constant _FAIL_VALUE = 0xffffffff;

    ////////////////////////////////////////////////////////////////////////
    // Signature Validation
    ////////////////////////////////////////////////////////////////////////

    /// @dev This function validates recovery by checking if digest equals expected recovery data hash.
    /// @dev The digest should be the recovery data hash from the guardian votes.
    /// @dev Signature parameter is not used since we validate against the digest directly.
    /// @dev This is a view function - recovery completion must be done via markRecoveryCompleted.
    function isValidSignatureWithKeyHash(
        bytes32 digest,
        bytes32, /* keyHash */
        bytes memory /* signature */
    ) external view override returns (bytes4 magicValue) {
        // Get the account address (msg.sender should be the IthacaAccount)
        address account = msg.sender;

        // Verify that recovery is in progress and ready
        RecoveryStorage storage $ = _getRecoveryStorage();
        bytes32 recoveryDataHash = $.recoveryDataHash[account];
        if (recoveryDataHash == bytes32(0)) {
            revert RecoveryNotInProgress();
        }
        RecoveryConfig memory recoveryConfig = getRecoveryConfig(account);
        uint128 recoveryRequestTime = $.recoveryRequestTime[account];
        uint128 executeAfter;
        uint128 executeBefore;
        unchecked {
            executeAfter = recoveryRequestTime + recoveryConfig.delay;
            executeBefore = executeAfter + recoveryConfig.expiry;
        }
        if (block.timestamp < executeAfter) return _FAIL_VALUE; // Not ready yet
        if (block.timestamp > executeBefore) return _FAIL_VALUE; // Expired

        uint8 threshold = getThreshold(account);
        if ($.guardianVotedMapping[account].length() < threshold) {
            return _FAIL_VALUE; // Insufficient weight
        }

        // The digest must equal the recovery data hash for validation to succeed
        if (digest != recoveryDataHash) return _FAIL_VALUE;

        return _MAGIC_VALUE;
    }

    function markRecoveryCompleted() external {
        _markRecoveryCompleted();
    }
}
