// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {EmailAuth, EmailAuthMsg} from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import {IthacaAccount} from "./IthacaAccount.sol";
import {IEmailRecoveryCommandHandler} from "./interfaces/IEmailRecoveryCommandHandler.sol";
import {ERC1967Factory} from "solady/utils/ERC1967Factory.sol";
import {GuardianManager} from "./GuardianManager.sol";
import {LibGuardianMap} from "./libraries/LibGuardianMap.sol";
import {LibGuardianConfig, GuardianConfig} from "./libraries/LibGuardianConfig.sol";
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

    /// @notice Constructs the EmailRecoveryManager contract with required dependencies and configuration.
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
    ) {
        if (_verifier == address(0)) revert InvalidVerifier();
        if (_dkim == address(0)) revert InvalidDkim();
        if (_emailAuthImpl == address(0)) revert InvalidEmailAuthImpl();
        if (_commandHandler == address(0)) revert InvalidCommandHandler();
        if (_factory == address(0)) revert InvalidFactory();
        if (_minimumDelay == 0) revert InvalidMinimumDelay();

        verifier = _verifier;
        dkim = _dkim;
        emailAuthImplementation = _emailAuthImpl;
        commandHandler = _commandHandler;
        minimumDelay = _minimumDelay;
        factory = ERC1967Factory(_factory);
    }

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

    /// @dev The account address in email is invalid (zero address)
    error InvalidAccountInEmail();
    /// @dev The template ID provided is invalid
    error InvalidTemplateId();
    /// @dev The isCodeExist flag is false
    error IsCodeExistFalse();
    /// @dev The guardian contract is not deployed
    error GuardianNotDeployed();
    /// @dev The controller address is invalid
    error InvalidController();
    /// @dev Setup function has already been called
    error SetupAlreadyCalled();
    /// @dev The threshold is not set
    error ThresholdNotSet();
    /// @dev The delay value is invalid
    error InvalidDelay();
    /// @dev The expiry value is invalid
    error InvalidExpiry();
    /// @dev A recovery process is already in progress
    error RecoveryInProcess();
    /// @dev Recovery is not activated for the account
    error RecoveryIsNotActivated();
    /// @dev The guardian has not been requested
    error GuardianNotRequested();
    /// @dev The guardian has already accepted
    error GuardianAlreadyAccepted();
    /// @dev The threshold exceeds the accepted guardian weight
    error ThresholdExceedsAcceptedWeight();
    /// @dev The guardian has not accepted
    error GuardianNotAccepted();
    /// @dev The guardian has already voted
    error GuardianAlreadyVoted();
    /// @dev The recovery data hash is invalid
    error InvalidRecoveryDataHash(bytes32 recoveryDataHash, bytes32 cachedRecoveryDataHash);
    /// @dev The verifier address is invalid (zero address)
    error InvalidVerifier();
    /// @dev The DKIM address is invalid (zero address)
    error InvalidDkim();
    /// @dev The email auth implementation address is invalid (zero address)
    error InvalidEmailAuthImpl();
    /// @dev The command handler address is invalid (zero address)
    error InvalidCommandHandler();
    /// @dev The factory address is invalid (zero address)
    error InvalidFactory();
    /// @dev The minimum delay is invalid (zero)
    error InvalidMinimumDelay();
    /// @dev The recovery is not in progress
    error RecoveryNotInProgress();

    ////////////////////////////////////////////////////////////////////////
    // Events
    ////////////////////////////////////////////////////////////////////////

    event RecoveryConfigured(address indexed account, uint256 guardianCount, uint8 threshold);
    event RecoveryConfigUpdated(address indexed account, uint128 delay, uint128 expiry);
    event GuardianAccepted(address indexed account, address indexed guardian);
    event GuardianVoted(address indexed account, address indexed guardian);
    event RecoveryRequestStarted(
        address indexed account, address indexed guardian, uint128 expiry, bytes32 recoveryDataHash
    );
    event RecoveryRequestCompleted(address indexed account, bytes32 recoveryDataHash);
    event RecoveryCancelled(address indexed account);
    event RecoveryCompleted(address indexed account, bytes32 recoveryDataHash);

    ////////////////////////////////////////////////////////////////////////
    // View Functions
    ////////////////////////////////////////////////////////////////////////

    /// @notice Returns if the account to be recovered has already activated the controller (this contract).
    /// @dev This function is virtual and should be implemented by inheriting contracts.
    /// @param recoveredAccount The address of the account to be recovered.
    /// @return True if the account is already activated, false otherwise.
    function isActivated(address recoveredAccount) public view virtual returns (bool);

    /// @notice Returns a two-dimensional array of strings representing the command templates for an acceptance by a new guardian's.
    /// @dev This function is virtual and should be implemented by inheriting contracts to define specific acceptance command templates.
    /// @return A two-dimensional array of strings, where each inner array represents a set of fixed strings and matchers for a command template.
    function acceptanceCommandTemplates() public view virtual returns (string[][] memory);

    /// @notice Returns a two-dimensional array of strings representing the command templates for email recovery.
    /// @dev This function is virtual and should be implemented by inheriting contracts to define specific recovery command templates.
    /// @return A two-dimensional array of strings, where each inner array represents a set of fixed strings and matchers for a command template.
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

    /// @notice Computes the address for email auth contract using the ERC1967Factory contract.
    /// @dev This function utilizes the `ERC1967Factory` contract to compute the address. The computation uses a provided account address to be recovered, account salt,
    /// and the hash of the encoded ERC1967Proxy creation code concatenated with the encoded email auth contract implementation
    /// address and the initialization call data. This ensures that the computed address is deterministic and unique per account salt.
    /// @param recoveredAccount The address of the account to be recovered.
    /// @param accountSalt A bytes32 salt value defined as a hash of the guardian's email address and an account code. This is assumed to be unique to a pair of the guardian's email address and the wallet address to be recovered.
    /// @return The computed address.
    function computeEmailAuthAddress(address recoveredAccount, bytes32 accountSalt)
        public
        view
        virtual
        returns (address)
    {
        // Generate salt with current contract address + last 12 bytes of hash
        bytes32 hashResult = keccak256(abi.encodePacked(recoveredAccount, accountSalt));
        bytes32 salt = bytes32(abi.encodePacked(address(this), bytes12(hashResult)));
        return factory.predictDeterministicAddress(salt);
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
        // Generate salt with current contract address + last 12 bytes of hash
        bytes32 hashResult = keccak256(abi.encodePacked(recoveredAccount, accountSalt));
        bytes32 salt = bytes32(abi.encodePacked(address(this), bytes12(hashResult)));
        return factory.deployDeterministicAndCall(
            emailAuthImplementation,
            address(this),
            salt,
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
            let ptr := mload(0x40)
            mstore(ptr, EMAIL_ACCOUNT_RECOVERY_VERSION_ID)
            mstore(add(ptr, 0x20), "ACCEPTANCE")
            mstore(add(ptr, 0x40), templateIdx)
            templateId := keccak256(ptr, 0x60)
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
            let ptr := mload(0x40)
            mstore(ptr, EMAIL_ACCOUNT_RECOVERY_VERSION_ID)
            mstore(add(ptr, 0x20), "RECOVERY")
            mstore(add(ptr, 0x40), templateIdx)
            templateId := keccak256(ptr, 0x60)
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
        _acceptGuardian(
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
        uint256 templateId = computeRecoveryTemplateId(templateIdx);
        if (templateId != emailAuthMsg.templateId) revert InvalidTemplateId();

        EmailAuth guardianEmailAuth = EmailAuth(payable(address(guardian)));

        // An assertion to confirm that the authEmail function is executed successfully
        // and does not return an error.
        guardianEmailAuth.authEmail(emailAuthMsg);

        _processRecovery(
            guardian, templateIdx, emailAuthMsg.commandParams, emailAuthMsg.proof.emailNullifier
        );
    }

    function configureRecovery(
        address[] calldata guardians,
        uint8 threshold,
        uint128 delay,
        uint128 expiry
    ) external {
        address account = msg.sender;

        // // Threshold can only be 0 at initialization.
        // // Check ensures that setup function can only be called once.
        if (getThreshold(account) > 0) {
            revert SetupAlreadyCalled();
        }
        _setupGuardians(account, guardians, threshold);
        
        // Set recovery config inline
        if (delay < minimumDelay) {
            revert InvalidDelay();
        }
        if (delay > expiry) {
            revert InvalidExpiry();
        }
        RecoveryStorage storage $ = _getRecoveryStorage();
        $.recoveryConfig[account].set(abi.encodePacked(delay, expiry));

        emit RecoveryConfigured(account, guardians.length, threshold);
    }

    function updateRecoveryConfig(uint128 delay, uint128 expiry) external {
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

        emit RecoveryConfigUpdated(account, delay, expiry);
    }

    ////////////////////////////////////////////////////////////////////////
    // Acceptance Functions
    ////////////////////////////////////////////////////////////////////////

    function _acceptGuardian(
        address guardian,
        uint256 templateIdx,
        bytes[] memory commandParams,
        bytes32 /* nullifier */
    ) internal virtual {
        address account = IEmailRecoveryCommandHandler(commandHandler).validateAcceptanceCommand(
            templateIdx, commandParams
        );

        RecoveryStorage storage $ = _getRecoveryStorage();
        if ($.recoveryDataHash[account] != bytes32(0)) {
            revert RecoveryInProcess();
        }

        if (!isActivated(account)) {
            revert RecoveryIsNotActivated();
        }

        uint8 status = getGuardian(account, guardian);
        if (status != uint8(LibGuardianMap.GuardianStatus.REQUESTED)) {
            revert GuardianNotRequested();
        }

        _updateGuardianStatus(account, guardian, LibGuardianMap.GuardianStatus.ACCEPTED);

        emit GuardianAccepted(account, guardian);
    }

    ////////////////////////////////////////////////////////////////////////
    // Recovery Functions
    ////////////////////////////////////////////////////////////////////////

    function _processRecovery(
        address guardian,
        uint256 templateIdx,
        bytes[] memory commandParams,
        bytes32 /* nullifier */
    ) internal virtual {
        address account = IEmailRecoveryCommandHandler(commandHandler).validateRecoveryCommand(
            templateIdx, commandParams
        );

        if (!isActivated(account)) {
            revert RecoveryIsNotActivated();
        }

        GuardianConfig memory guardianConfig = _getGuardianConfig(account);
        if (guardianConfig.threshold > guardianConfig.acceptedCount) {
            revert ThresholdExceedsAcceptedWeight();
        }

        uint8 status = getGuardian(account, guardian);
        if (status != uint8(LibGuardianMap.GuardianStatus.ACCEPTED)) {
            revert GuardianNotAccepted();
        }

        RecoveryStorage storage $ = _getRecoveryStorage();
        bytes32 recoveryDataHash = IEmailRecoveryCommandHandler(commandHandler)
            .parseRecoveryDataHash(templateIdx, commandParams);

        if ($.guardianVotedMapping[account].contains(guardian)) {
            revert GuardianAlreadyVoted();
        }

        uint8 guardianCount = guardianConfig.guardianCount;
        // bool cooldownNotExpired =
        //     previousRecoveryRequests[account].cancelRecoveryCooldown > block.timestamp;
        // if (
        //     previousRecoveryRequests[account].previousGuardianInitiated == guardian
        //         && cooldownNotExpired && guardianCount > 1
        // ) {
        //     revert GuardianMustWaitForCooldown(guardian);
        // }
        bytes32 cachedRecoveryDataHash = $.recoveryDataHash[account];
        if (cachedRecoveryDataHash == bytes32(0)) {
            $.recoveryDataHash[account] = recoveryDataHash;
            // previousRecoveryRequests[account]
            //     .previousGuardianInitiated = guardian;
            $.recoveryRequestTime[account] = uint128(block.timestamp);
            RecoveryConfig memory recoveryConfig = getRecoveryConfig(account);
            uint128 expiryTime;
            unchecked {
                expiryTime = uint128(block.timestamp) + recoveryConfig.expiry;
            }
            emit RecoveryRequestStarted(account, guardian, expiryTime, recoveryDataHash);
        } else if (cachedRecoveryDataHash != recoveryDataHash) {
            revert InvalidRecoveryDataHash(recoveryDataHash, cachedRecoveryDataHash);
        }

        $.guardianVotedMapping[account].add(guardian);

        emit GuardianVoted(account, guardian);

        if ($.guardianVotedMapping[account].length() >= guardianConfig.threshold) {
            emit RecoveryRequestCompleted(account, recoveryDataHash);
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // Cancel Recovery Functions
    ////////////////////////////////////////////////////////////////////////

    function cancelRecovery() external {
        address account = msg.sender;
        RecoveryStorage storage $ = _getRecoveryStorage();
        if ($.recoveryDataHash[account] == bytes32(0)) {
            revert RecoveryNotInProgress();
        }
        $.recoveryDataHash[account] = bytes32(0);
        $.recoveryRequestTime[account] = 0;
        _clearGuardianVotedMapping(account);
        emit RecoveryCancelled(account);
    }

    function _clearGuardianVotedMapping(address account) internal {
        RecoveryStorage storage $ = _getRecoveryStorage();
        uint256 guardianCount = $.guardianVotedMapping[account].length();
        while (guardianCount > 0) {
            guardianCount--;
            $.guardianVotedMapping[account].remove($.guardianVotedMapping[account].at(guardianCount));
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // Complete Recovery Functions
    ////////////////////////////////////////////////////////////////////////

    function _markRecoveryCompleted() internal {
        address account = msg.sender;
        RecoveryStorage storage $ = _getRecoveryStorage();
        bytes32 recoveryDataHash = $.recoveryDataHash[account];
        if (recoveryDataHash == bytes32(0)) {
            revert RecoveryNotInProgress();
        }
        $.recoveryDataHash[account] = bytes32(0);
        $.recoveryRequestTime[account] = 0;
        _clearGuardianVotedMapping(account);
        emit RecoveryCompleted(account, recoveryDataHash);
    }
}
