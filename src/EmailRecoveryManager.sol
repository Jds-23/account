// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {EmailAuth, EmailAuthMsg} from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import {IthacaAccount} from "./IthacaAccount.sol";
import {IthacaAccountRecoveryCommandHandler} from "./IthacaAccountRecoveryCommandHandler.sol";
import {CREATE3} from "solady/utils/CREATE3.sol";
import {ERC1967Factory} from "solady/utils/ERC1967Factory.sol";
import {GuardianManager} from "./GuardianManager.sol";
import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";

abstract contract EmailRecoveryManager is GuardianManager {
    using LibBytes for LibBytes.BytesStorage;
    using EnumerableSetLib for EnumerableSetLib.AddressSet;

    ERC1967Factory public immutable factory;
    uint8 constant EMAIL_ACCOUNT_RECOVERY_VERSION_ID = 1;
    uint128 public constant MINIMUM_RECOVERY_WINDOW = 2 days;
    uint128 public constant CANCEL_EXPIRED_RECOVERY_COOLDOWN = 1 days;
    address public immutable verifier;
    address public immutable dkim;
    address public immutable emailAuthImplementation;
    address public immutable commandHandler;
    uint128 public immutable minimumDelay;

    // constructor(
    //     address _verifier,
    //     address _dkimRegistry,
    //     address _emailAuthImpl,
    //     address _commandHandler,
    //     uint256 _minimumDelay,
    //     address _killSwitchAuthorizer,
    //     address _factory // Ownable(_killSwitchAuthorizer)
    // ) {
    //     if (_verifier == address(0)) {
    //         revert InvalidVerifier();
    //     }
    //     if (_dkimRegistry == address(0)) {
    //         revert InvalidDkimRegistry();
    //     }
    //     if (_emailAuthImpl == address(0)) {
    //         revert InvalidEmailAuthImpl();
    //     }
    //     if (_commandHandler == address(0)) {
    //         revert InvalidCommandHandler();
    //     }
    //     if (_killSwitchAuthorizer == address(0)) {
    //         revert InvalidKillSwitchAuthorizer();
    //     }
    //     verifierAddr = _verifier;
    //     dkimAddr = _dkimRegistry;
    //     emailAuthImplementationAddr = _emailAuthImpl;
    //     commandHandler = _commandHandler;
    //     minimumDelay = _minimumDelay;
    //     factory = ERC1967Factory(_factory);
    // }

    ////////////////////////////////////////////////////////////////////////
    // Storage
    ////////////////////////////////////////////////////////////////////////
    struct RecoveryConfig {
        /// @dev The delay before the recovery can be completed.
        uint128 delay;
        /// @dev The expiry time for the recovery.
        uint128 expiry;
    }

    /// @dev Holds the storage.
    struct RecoveryStorage {
        /// @dev The recovery configuration.
        mapping(address => LibBytes.BytesStorage) recoveryConfig;
        /// @dev The recovery data hash.
        mapping(address => bytes32) recoveryDataHash;
        /// @dev The time when the recovery request was created.
        mapping(address => uint128) recoveryRequestTime;
        /// @dev The guardians that have voted for the recovery.
        mapping(address => EnumerableSetLib.AddressSet) guardianVotedMapping;
    }

    /// @dev Returns the storage pointer.
    function _getRecoveryStorage() internal pure returns (RecoveryStorage storage $) {
        // Truncate to 9 bytes to reduce bytecode size.
        uint256 s = uint72(bytes9(keccak256("ITHACA_RECOVERY_STORAGE")));
        assembly ("memory-safe") {
            $.slot := s
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // Custom Errors
    ////////////////////////////////////////////////////////////////////////

    error InvalidAccountInEmail();
    error InvalidTemplateId();
    error IsCodeExistFalse();
    error GuardianNotDeployed();
    error InvalidController();
    error SetupAlreadyCalled();
    error ThresholdNotSet();
    error InvalidDelay();
    error InvalidExpiry();

    ////////////////////////////////////////////////////////////////////////
    // Events
    ////////////////////////////////////////////////////////////////////////

    event RecoveryConfigured(address indexed account, uint256 guardianCount, uint8 threshold);

    ////////////////////////////////////////////////////////////////////////
    // View Functions
    ////////////////////////////////////////////////////////////////////////

    /// @notice Returns if the account to be recovered has already activated the controller (this contract).
    /// @dev This function is virtual and should be implemented by inheriting contracts.
    /// @dev This function helps a relayer inactivate the guardians' data after the account inactivates the controller (this contract).
    /// @param recoveredAccount The address of the account to be recovered.
    /// @return bool True if the account is already activated, false otherwise.
    function isActivated(address recoveredAccount) public view virtual returns (bool);

    /// @notice Returns a two-dimensional array of strings representing the command templates for an acceptance by a new guardian's.
    /// @dev This function is virtual and should be implemented by inheriting contracts to define specific acceptance command templates.
    /// @return string[][] A two-dimensional array of strings, where each inner array represents a set of fixed strings and matchers for a command template.
    function acceptanceCommandTemplates() public view virtual returns (string[][] memory);

    /// @notice Returns a two-dimensional array of strings representing the command templates for email recovery.
    /// @dev This function is virtual and should be implemented by inheriting contracts to define specific recovery command templates.
    /// @return string[][] A two-dimensional array of strings, where each inner array represents a set of fixed strings and matchers for a command template.
    function recoveryCommandTemplates() public view virtual returns (string[][] memory);

    /// @notice Extracts the account address to be recovered from the command parameters of an acceptance email.
    /// @dev This function is virtual and should be implemented by inheriting contracts to extract the account address from the command parameters.
    /// @param commandParams The command parameters of the acceptance email.
    /// @param templateIdx The index of the acceptance command template.
    function extractRecoveredAccountFromAcceptanceCommand(
        bytes[] memory commandParams,
        uint256 templateIdx
    ) public view virtual returns (address);

    /// @notice Extracts the account address to be recovered from the command parameters of a recovery email.
    /// @dev This function is virtual and should be implemented by inheriting contracts to extract the account address from the command parameters.
    /// @param commandParams The command parameters of the recovery email.
    /// @param templateIdx The index of the recovery command template.
    function extractRecoveredAccountFromRecoveryCommand(
        bytes[] memory commandParams,
        uint256 templateIdx
    ) public view virtual returns (address);

    function acceptGuardian(
        address guardian,
        uint256 templateIdx,
        bytes[] memory commandParams,
        bytes32 emailNullifier
    ) internal virtual;

    function processRecovery(
        address guardian,
        uint256 templateIdx,
        bytes[] memory commandParams,
        bytes32 emailNullifier
    ) internal virtual;

    /// @notice Completes the recovery process.
    /// @dev This function must be implemented by inheriting contracts to finalize the recovery process.
    /// @param account The address of the account to be recovered.
    /// @param completeCalldata The calldata for the recovery process.
    function completeRecovery(address account, bytes memory completeCalldata) external virtual;

    /// @notice Computes the address for email auth contract using the ERC1967Factory contract.
    /// @dev This function utilizes the `ERC1967Factory` contract to compute the address. The computation uses a provided account address to be recovered, account salt,
    /// and the hash of the encoded ERC1967Proxy creation code concatenated with the encoded email auth contract implementation
    /// address and the initialization call data. This ensures that the computed address is deterministic and unique per account salt.
    /// @param recoveredAccount The address of the account to be recovered.
    /// @param accountSalt A bytes32 salt value defined as a hash of the guardian's email address and an account code. This is assumed to be unique to a pair of the guardian's email address and the wallet address to be recovered.
    /// @return address The computed address.
    function computeEmailAuthAddress(address recoveredAccount, bytes32 accountSalt)
        public
        view
        virtual
        returns (address)
    {
        return factory.predictDeterministicAddress(
            keccak256(abi.encodePacked(recoveredAccount, accountSalt))
        );
    }

    /// @dev Returns the recovery config for the account.
    function getRecoveryConfig(address account)
        public
        view
        returns (RecoveryConfig memory config)
    {
        bytes memory data = _getRecoveryStorage().recoveryConfig[account].get();
        unchecked {
            uint256 packed = uint256(LibBytes.load(data, 0));
            config.delay = uint128(packed >> 128);
            config.expiry = uint128(packed);
        }
    }

    /// @notice Deploys a new proxy contract for email authentication.
    /// @dev This function uses the ERC1967Factory to deploy a new ERC1967Proxy contract with a deterministic address.
    /// @param recoveredAccount The address of the account to be recovered.
    /// @param accountSalt A bytes32 salt value used to ensure the uniqueness of the deployed proxy address.
    /// @return address The address of the newly deployed proxy contract.
    function deployEmailAuthProxy(address recoveredAccount, bytes32 accountSalt)
        internal
        virtual
        returns (address)
    {
        return factory.deployDeterministicAndCall(
            emailAuthImplementation,
            address(this),
            keccak256(abi.encodePacked(recoveredAccount, accountSalt)),
            abi.encodeCall(EmailAuth.initialize, (recoveredAccount, accountSalt, address(this)))
        );
    }

    /// @notice Calculates a unique command template ID for an acceptance command template using its index.
    /// @dev Encodes the email account recovery version ID, "ACCEPTANCE", and the template index,
    /// then uses keccak256 to hash these values into a uint ID.
    /// @param templateIdx The index of the acceptance command template.
    /// @return uint The computed uint ID.
    function computeAcceptanceTemplateId(uint256 templateIdx) public pure returns (uint256) {
        uint256 templateId;
        assembly ("memory-safe") {
            mstore(0x00, EMAIL_ACCOUNT_RECOVERY_VERSION_ID)
            mstore(0x20, "ACCEPTANCE")
            mstore(0x40, templateIdx)
            templateId := keccak256(0x00, 0x60)
        }
        return templateId;
    }

    /// @notice Calculates a unique ID for a recovery command template using its index.
    /// @dev Encodes the email account recovery version ID, "RECOVERY", and the template index,
    /// then uses keccak256 to hash these values into a uint256 ID.
    /// @param templateIdx The index of the recovery command template.
    /// @return uint The computed uint ID.
    function computeRecoveryTemplateId(uint256 templateIdx) public pure returns (uint256) {
        uint256 templateId;
        assembly ("memory-safe") {
            mstore(0x00, EMAIL_ACCOUNT_RECOVERY_VERSION_ID)
            mstore(0x20, "RECOVERY")
            mstore(0x40, templateIdx)
            templateId := keccak256(0x00, 0x60)
        }
        return templateId;
    }

    /// @notice Handles an acceptance by a new guardian.
    /// @dev This function validates the email auth message, deploys a new EmailAuth contract as a proxy if validations pass and initializes the contract.
    /// @param emailAuthMsg The email auth message for the email send from the guardian.
    /// @param templateIdx The index of the command template for acceptance, which should match with the command in the given email auth message.
    function handleAcceptance(EmailAuthMsg memory emailAuthMsg, uint256 templateIdx) external {
        address recoveredAccount =
            extractRecoveredAccountFromAcceptanceCommand(emailAuthMsg.commandParams, templateIdx);
        if (recoveredAccount == address(0)) revert InvalidAccountInEmail();
        address guardian = computeEmailAuthAddress(recoveredAccount, emailAuthMsg.proof.accountSalt);
        uint256 templateId = computeAcceptanceTemplateId(templateIdx);
        if (templateId != emailAuthMsg.templateId) revert InvalidTemplateId();
        if (emailAuthMsg.proof.isCodeExist == false) revert IsCodeExistFalse();

        EmailAuth guardianEmailAuth;
        if (guardian.code.length == 0) {
            address proxyAddress =
                deployEmailAuthProxy(recoveredAccount, emailAuthMsg.proof.accountSalt);
            guardianEmailAuth = EmailAuth(proxyAddress);
            guardianEmailAuth.initDKIMRegistry(dkim);
            guardianEmailAuth.initVerifier(verifier);
            string[][] memory acceptanceTemplates = acceptanceCommandTemplates();
            uint256 acceptanceLength = acceptanceTemplates.length;
            for (uint256 idx; idx < acceptanceLength;) {
                guardianEmailAuth.insertCommandTemplate(
                    computeAcceptanceTemplateId(idx), acceptanceTemplates[idx]
                );
                unchecked {
                    ++idx;
                }
            }
            string[][] memory recoveryTemplates = recoveryCommandTemplates();
            uint256 recoveryLength = recoveryTemplates.length;
            for (uint256 idx; idx < recoveryLength;) {
                guardianEmailAuth.insertCommandTemplate(
                    computeRecoveryTemplateId(idx), recoveryTemplates[idx]
                );
                unchecked {
                    ++idx;
                }
            }
        } else {
            guardianEmailAuth = EmailAuth(payable(address(guardian)));
            if (guardianEmailAuth.controller() != address(this)) {
                revert InvalidController();
            }
        }

        // An assertion to confirm that the authEmail function is executed successfully
        // and does not return an error.
        guardianEmailAuth.authEmail(emailAuthMsg);
        acceptGuardian(
            guardian, templateIdx, emailAuthMsg.commandParams, emailAuthMsg.proof.emailNullifier
        );
    }

    /// @notice Processes the recovery based on an email from the guardian.
    /// @dev Verify the provided email auth message for a deployed guardian's EmailAuth contract and a specific command template for recovery.
    /// Requires that the guardian is already deployed, and the template ID corresponds to the `templateId` in the given email auth message. Once validated.
    /// @param emailAuthMsg The email auth message for recovery.
    /// @param templateIdx The index of the command template for recovery, which should match with the command in the given email auth message.
    function handleRecovery(EmailAuthMsg memory emailAuthMsg, uint256 templateIdx) external {
        address recoveredAccount =
            extractRecoveredAccountFromRecoveryCommand(emailAuthMsg.commandParams, templateIdx);
        if (recoveredAccount == address(0)) revert InvalidAccountInEmail();
        address guardian = computeEmailAuthAddress(recoveredAccount, emailAuthMsg.proof.accountSalt);
        // Check if the guardian is deployed
        if (address(guardian).code.length == 0) revert GuardianNotDeployed();
        uint256 templateId = uint256(
            keccak256(abi.encode(EMAIL_ACCOUNT_RECOVERY_VERSION_ID, "RECOVERY", templateIdx))
        );
        if (templateId != emailAuthMsg.templateId) revert InvalidTemplateId();

        EmailAuth guardianEmailAuth = EmailAuth(payable(address(guardian)));

        // An assertion to confirm that the authEmail function is executed successfully
        // and does not return an error.
        guardianEmailAuth.authEmail(emailAuthMsg);

        processRecovery(
            guardian, templateIdx, emailAuthMsg.commandParams, emailAuthMsg.proof.emailNullifier
        );
    }

    function configureRecovery(
        address[] calldata guardians,
        uint8 threshold,
        uint128 delay,
        uint128 expiry
    ) internal {
        address account = msg.sender;

        // // Threshold can only be 0 at initialization.
        // // Check ensures that setup function can only be called once.
        if (getThreshold(account) > 0) {
            revert SetupAlreadyCalled();
        }
        _setupGuardians(account, guardians, threshold);
        updateRecoveryConfig(delay, expiry);

        emit RecoveryConfigured(account, guardians.length, threshold);
    }

    function updateRecoveryConfig(uint128 delay, uint128 expiry) internal {
        address account = msg.sender;
        if (getThreshold(account) == 0) {
            revert ThresholdNotSet();
        }
        if (delay < minimumDelay) {
            revert InvalidDelay();
        }
        if (delay > expiry) {
            revert InvalidExpiry();
        }
        RecoveryStorage storage $ = _getRecoveryStorage();
        $.recoveryConfig[account].set(abi.encodePacked(delay, expiry));
    }
}
