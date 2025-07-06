// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {LibBytes} from "solady/utils/LibBytes.sol";
import {EnumerableMapLib} from "solady/utils/EnumerableMapLib.sol";
import {LibGuardianMap} from "./libraries/LibGuardianMap.sol";
import {LibGuardianConfig} from "./libraries/LibGuardianConfig.sol";

abstract contract GuardianManager {
    using LibBytes for LibBytes.BytesStorage;
    using EnumerableMapLib for EnumerableMapLib.AddressToUint256Map;
    using LibGuardianMap for EnumerableMapLib.AddressToUint256Map;
    using LibGuardianConfig for LibBytes.BytesStorage;

    ////////////////////////////////////////////////////////////////////////
    // Storage
    ////////////////////////////////////////////////////////////////////////

    /// @dev Holds the storage.
    struct GuardianStorage {
        /// @dev The guardian configuration.
        mapping(address => LibBytes.BytesStorage) accountGuardiansConfig;
        /// @dev The guardians.
        mapping(address => EnumerableMapLib.AddressToUint256Map) accountGuardians;
    }

    // function _getGuardianConfig(address account)
    //     internal
    //     view
    //     returns (GuardianConfig memory config)
    // {
    //     return LibGuardianConfig.loadConfig(accountGuardiansConfig[account]);
    // }

    /// @dev Returns the storage pointer.
    function _getGuardianStorage()
        internal
        pure
        returns (GuardianStorage storage $)
    {
        // Truncate to 9 bytes to reduce bytecode size.
        uint256 s = uint72(bytes9(keccak256("ITHACA_GUARDIAN_STORAGE")));
        assembly ("memory-safe") {
            $.slot := s
        }
    }

    ////////////////////////////////////////////////////////////////////////
    // Errors
    ////////////////////////////////////////////////////////////////////////

    /// @dev The guardian is invalid. (0 address or self)
    error InvalidGuardian();

    /// @dev The threshold is invalid. (0 or greater than the number of guardians)
    error InvalidThreshold();

    /// @dev The guardian is not accepted.
    error GuardianNotAdded();

    /// @dev The guardian status update failed.
    error GuardianStatusUpdateFailed();

    ////////////////////////////////////////////////////////////////////////
    // Events
    ////////////////////////////////////////////////////////////////////////

    /// @dev The guardian has been added.
    event GuardianAdded(address indexed account, address guardian);

    /// @dev The guardian has been removed.
    event GuardianRemoved(address indexed account, address guardian);

    /// @dev The guardian status has been changed.
    event GuardianStatusChanged(
        address indexed account,
        address indexed guardian,
        LibGuardianMap.GuardianStatus status
    );

    /// @dev The threshold has been changed.
    event ThresholdChanged(address indexed account, uint8 threshold);

    ////////////////////////////////////////////////////////////////////////
    // Internal Functions
    ////////////////////////////////////////////////////////////////////////

    /**
     * @notice Sets up guardians for a given account with specified weights and threshold
     * @dev This function can only be called once and ensures the guardians, weights, and threshold
     * are correctly configured
     * @param account The address of the account for which guardians are being set up
     * @param guardians An array of guardian addresses
     * @param threshold The threshold weight required for guardians to approve recovery attempts
     */
    function _setupGuardians(
        address account,
        address[] calldata guardians,
        uint8 threshold
    ) internal {
        GuardianStorage storage $ = _getGuardianStorage();
        $.accountGuardiansConfig[account].initConfig(
            uint8(guardians.length),
            threshold
        );
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == address(0) || guardians[i] == account)
                revert InvalidGuardian();
            $.accountGuardians[account].addGuardian(guardians[i]); // add with status REQUESTED
            emit GuardianAdded(account, guardians[i]);
        }
    }

    /**
     * @notice Internal fucntion to add a guardian for the caller's account with a specified weight
     * @dev A guardian is added, but not accepted after this function has been called
     * @param guardian The address of the guardian to be added
     */
    function _addGuardian(address account, address guardian) internal {
        GuardianStorage storage $ = _getGuardianStorage();
        if (guardian == address(0) || guardian == account)
            revert InvalidGuardian();
        $.accountGuardians[account].addGuardian(guardian);
        $.accountGuardiansConfig[account].incrementGuardianCount();
        emit GuardianAdded(account, guardian);
    }

    /**
     * @notice Internal function to remove a guardian for the caller's account
     * @dev A guardian is removed, but not accepted after this function has been called
     * @param guardian The address of the guardian to be removed
     */
    function _removeGuardian(address account, address guardian) internal {
        GuardianStorage storage $ = _getGuardianStorage();

        // Check if guardian is accepted before removal
        bool wasAccepted = $.accountGuardians[account].isAccepted(guardian);

        $.accountGuardians[account].removeGuardian(guardian);

        $.accountGuardiansConfig[account].decrementGuardianCount();
        if (wasAccepted) {
            $.accountGuardiansConfig[account].decrementAcceptedCount();
        }
        emit GuardianRemoved(account, guardian);
    }

    /**
     * @notice Changes the threshold for guardian approvals for the caller's account
     * @dev This function can only be called by the account associated with the guardian config and
     * only if no recovery is in process
     * @param threshold The new threshold for guardian approvals
     */
    function _changeThreshold(address account, uint8 threshold) internal {
        GuardianStorage storage $ = _getGuardianStorage();
        $.accountGuardiansConfig[account].setThreshold(threshold);
        emit ThresholdChanged(account, threshold);
    }

    /**
     * @notice Updates the status for a guardian
     * @param account The address of the account associated with the guardian
     * @param guardian The address of the guardian
     * @param newStatus The new status for the guardian
     */
    function _updateGuardianStatus(
        address account,
        address guardian,
        LibGuardianMap.GuardianStatus newStatus
    ) internal {
        GuardianStorage storage $ = _getGuardianStorage();
        if (!$.accountGuardians[account].contains(guardian))
            revert GuardianNotAdded();

        $.accountGuardians[account].updateStatus(guardian, newStatus);
        $.accountGuardiansConfig[account].incrementAcceptedCount();
        emit GuardianStatusChanged(account, guardian, newStatus);
    }
}
