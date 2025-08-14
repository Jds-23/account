// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IIthacaAccount} from "./interfaces/IIthacaAccount.sol";
import {ISigner} from "./interfaces/ISigner.sol";
import {EmailRecoveryManager} from "./EmailRecoveryManager.sol";
import {IEmailRecoveryCommandHandler} from "./interfaces/IEmailRecoveryCommandHandler.sol";
import {GuardianConfig} from "./libraries/LibGuardianConfig.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";

/// @notice Error thrown when command parameters are invalid.
error InvalidCommandParams();

/// @notice Error thrown when recovery is not ready to be completed.
error RecoveryNotReady();

/// @title ZKEmailSigner
/// @notice A Signer contract, that extends ZK-email functionality to the Porto Account.
contract ZKEmailSigner is ISigner, EmailRecoveryManager {
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    ////////////////////////////////////////////////////////////////////////
    // Constants
    ////////////////////////////////////////////////////////////////////////

    /// @dev The magic value returned by `isValidSignatureWithKeyHash` when the signature is valid.
    bytes4 internal constant _MAGIC_VALUE = 0x8afc93b4;

    /// @dev The magic value returned by `isValidSignatureWithKeyHash` when the signature is invalid.
    bytes4 internal constant _FAIL_VALUE = 0xffffffff;

    ////////////////////////////////////////////////////////////////////////
    // Constructor
    ////////////////////////////////////////////////////////////////////////

    /// @notice Constructs the ZKEmailSigner with required EmailRecoveryManager dependencies.
    /// @param _verifier The verifier contract address.
    /// @param _dkim The DKIM registry contract address.
    /// @param _emailAuthImpl The email auth implementation contract address.
    /// @param _commandHandler The command handler contract address.
    /// @param _minimumDelay The minimum delay for recovery.
    /// @param _factory The ERC1967Factory contract address.
    constructor(
        address _verifier,
        address _dkim,
        address _emailAuthImpl,
        address _commandHandler,
        uint128 _minimumDelay,
        address _factory
    )
        EmailRecoveryManager(_verifier, _dkim, _emailAuthImpl, _commandHandler, _minimumDelay, _factory)
    {}

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

    ////////////////////////////////////////////////////////////////////////
    // Required EmailRecoveryManager Implementations
    ////////////////////////////////////////////////////////////////////////

    /// @notice Returns if the account has activated this recovery manager.
    function isActivated(address recoveredAccount) public view override returns (bool) {
        // Check if recovery config exists for this account
        GuardianConfig memory config = _getGuardianConfig(recoveredAccount);
        return config.threshold > 0;
    }

    /// @notice Returns command templates for guardian acceptance emails.
    function acceptanceCommandTemplates() public view override returns (string[][] memory) {
        return IEmailRecoveryCommandHandler(commandHandler).acceptanceCommandTemplates();
    }

    /// @notice Returns command templates for recovery emails.
    function recoveryCommandTemplates() public view override returns (string[][] memory) {
        return IEmailRecoveryCommandHandler(commandHandler).recoveryCommandTemplates();
    }

    /// @notice Extracts the account address from acceptance command parameters.
    function extractRecoveredAccountFromAcceptanceCommand(
        bytes[] memory commandParams,
        uint256 templateIdx
    ) public view override returns (address) {
        return IEmailRecoveryCommandHandler(commandHandler)
            .extractRecoveredAccountFromAcceptanceCommand(commandParams, templateIdx);
    }

    /// @notice Extracts the account address from recovery command parameters.
    function extractRecoveredAccountFromRecoveryCommand(
        bytes[] memory commandParams,
        uint256 templateIdx
    ) public view override returns (address) {
        return IEmailRecoveryCommandHandler(commandHandler)
            .extractRecoveredAccountFromRecoveryCommand(commandParams, templateIdx);
    }
}
