// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IEmailRecoveryCommandHandler} from "./interfaces/IEmailRecoveryCommandHandler.sol";
import {IIthacaAccount} from "./interfaces/IIthacaAccount.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";
import {ZKEmailSigner} from "./ZKEmailSigner.sol";
import {IthacaAccount} from "./IthacaAccount.sol";
import {StringUtils} from "@zk-email/ether-email-auth-contracts/src/libraries/StringUtils.sol";

/// @title IthacaAccountRecoveryCommandHandler
/// @notice Custom command handler for IthacaAccount email recovery
/// @dev Handles commands for accepting guardians and recovering specific keys
contract IthacaAccountRecoveryCommandHandler is IEmailRecoveryCommandHandler {
    ZKEmailSigner public immutable zkEmailSigner;

    constructor(address _zkEmailSigner) {
        zkEmailSigner = ZKEmailSigner(_zkEmailSigner);
    }

    ////////////////////////////////////////////////////////////////////////
    // Errors
    ////////////////////////////////////////////////////////////////////////

    error InvalidTemplateIndex();
    error InvalidCommandParams();
    error InvalidAccountAddress();
    error InvalidKeyHash();
    error InvalidKeyData();
    error InvalidHexString();

    ////////////////////////////////////////////////////////////////////////
    // Constants
    ////////////////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////////////////
    // IEmailRecoveryCommandHandler Implementation
    ////////////////////////////////////////////////////////////////////////

    /// @inheritdoc IEmailRecoveryCommandHandler
    function acceptanceCommandTemplates() external pure override returns (string[][] memory) {
        string[][] memory templates = new string[][](1);
        templates[0] = new string[](5);
        templates[0][0] = "Accept";
        templates[0][1] = "guardian";
        templates[0][2] = "request";
        templates[0][3] = "for";
        templates[0][4] = "{ethAddr}";
        return templates;
    }

    /// @inheritdoc IEmailRecoveryCommandHandler
    function recoveryCommandTemplates() external pure override returns (string[][] memory) {
        string[][] memory templates = new string[][](1);
        templates[0] = new string[](9);
        templates[0][0] = "Recover";
        templates[0][1] = "account";
        templates[0][2] = "{ethAddr}";
        templates[0][3] = "by";
        templates[0][4] = "replacing";
        templates[0][5] = "key";
        templates[0][6] = "{string}";
        templates[0][7] = "with";
        templates[0][8] = "{string}";
        return templates;
    }

    /// @inheritdoc IEmailRecoveryCommandHandler
    function extractRecoveredAccountFromAcceptanceCommand(
        bytes[] memory commandParams,
        uint256 /* templateIdx */
    ) external pure override returns (address) {
        // For template 0: ["Accept", "guardian", "request", "for", "{ethAddr}"]
        // commandParams[0] should be the account address
        address account = abi.decode(commandParams[0], (address));
        return account;
    }

    /// @inheritdoc IEmailRecoveryCommandHandler
    function extractRecoveredAccountFromRecoveryCommand(
        bytes[] memory commandParams,
        uint256 /* templateIdx */
    ) external pure override returns (address) {
        // For template 0: ["Recover", "account", "{ethAddr}", "by", "replacing", "key", "{string}", "with", "{string}"]
        // commandParams[0] should be the account address
        address account = abi.decode(commandParams[0], (address));
        return account;
    }

    /// @inheritdoc IEmailRecoveryCommandHandler
    function validateAcceptanceCommand(uint256 templateIdx, bytes[] memory commandParams)
        external
        view
        override
        returns (address)
    {
        if (templateIdx >= this.acceptanceCommandTemplates().length) {
            revert InvalidTemplateIndex();
        }

        // For template 0: ["Accept", "guardian", "request", "for", "{ethAddr}"]
        // commandParams[0] should be the account address
        if (commandParams.length != 1) {
            revert InvalidCommandParams();
        }

        address account =
            this.extractRecoveredAccountFromAcceptanceCommand(commandParams, templateIdx);
        if (account == address(0)) {
            revert InvalidAccountAddress();
        }

        return account;
    }

    /// @inheritdoc IEmailRecoveryCommandHandler
    function validateRecoveryCommand(uint256 templateIdx, bytes[] memory commandParams)
        external
        view
        override
        returns (address)
    {
        if (templateIdx >= this.recoveryCommandTemplates().length) {
            revert InvalidTemplateIndex();
        }

        // For template 0: ["Recover", "account", "{ethAddr}", "by", "replacing", "key", "{string}", "with", "{string}"]
        // commandParams[0] should be the account address
        if (commandParams.length != 3) {
            revert InvalidCommandParams();
        }

        address account =
            this.extractRecoveredAccountFromRecoveryCommand(commandParams, templateIdx);
        if (account == address(0)) {
            revert InvalidAccountAddress();
        }

        // Additional validation for recovery command
        if (templateIdx == 0) {
            // Validate key hash - should be a hex string from {string} parameter
            string memory keyHashStr = abi.decode(commandParams[1], (string));
            try StringUtils.hexToBytes32(keyHashStr) returns (bytes32 keyHashToRevoke) {
                if (keyHashToRevoke == bytes32(0)) {
                    revert InvalidKeyHash();
                }
            } catch {
                revert InvalidHexString();
            }

            // Validate new key data - should be JSON string from {string} parameter
            string memory newKeyStr = abi.decode(commandParams[2], (string));
            if (bytes(newKeyStr).length == 0) {
                revert InvalidKeyData();
            }
        }

        return account;
    }

    /// @inheritdoc IEmailRecoveryCommandHandler
    function parseRecoveryDataHash(uint256 templateIdx, bytes[] memory commandParams)
        external
        view
        override
        returns (bytes32)
    {
        // Validate all parameters first
        address account = this.validateRecoveryCommand(templateIdx, commandParams);

        // Extract/decode data - {string} parameters come as string values
        string memory keyHashStr = abi.decode(commandParams[1], (string));
        bytes32 keyHashToRevoke = StringUtils.hexToBytes32(keyHashStr);

        string memory newKeyStr = abi.decode(commandParams[2], (string));
        // For now, we expect the new key to be ABI-encoded as a hex string
        // This might need adjustment based on the actual format expected
        bytes memory newKeyBytes = StringUtils.hexToBytes(newKeyStr);
        IthacaAccount.Key memory newKey = abi.decode(newKeyBytes, (IthacaAccount.Key));

        ERC7821.Call[] memory calls = new ERC7821.Call[](3);
        calls[0] = ERC7821.Call({
            to: account,
            value: 0,
            data: abi.encodeWithSelector(IthacaAccount.revoke.selector, keyHashToRevoke)
        });
        calls[1] = ERC7821.Call({
            to: account,
            value: 0,
            data: abi.encodeWithSelector(IthacaAccount.authorize.selector, newKey)
        });
        calls[2] = ERC7821.Call({
            to: address(zkEmailSigner),
            value: 0,
            data: abi.encodeWithSelector(ZKEmailSigner.markRecoveryCompleted.selector)
        });

        uint256 nonce = IIthacaAccount(account).getNonce(0);
        bytes32 digest = IIthacaAccount(account).computeDigest(calls, nonce);

        return digest;
    }
}
