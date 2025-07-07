// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {EnumerableMapLib} from "solady/utils/EnumerableMapLib.sol";

/// @title LibGuardianMap
/// @notice Library for managing guardian addresses with status tracking using EnumerableMap
/// @dev Efficiently maps address to status using EnumerableMapLib for gas optimization
library LibGuardianMap {
    using EnumerableMapLib for EnumerableMapLib.AddressToUint256Map;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ENUMS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Guardian status enumeration
    enum GuardianStatus {
        NONE, // 0 - Guardian doesn't exist (default for non-existent guardians)
        REQUESTED, // 1 - Guardian has been requested but not yet accepted
        ACCEPTED // 2 - Guardian has accepted their role

    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ERRORS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error GuardianAlreadyExists();
    error GuardianNotFound();
    error InvalidStatusTransition();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    CORE OPERATIONS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Add a new guardian with REQUESTED status
    /// @param self The guardian set storage
    /// @param guardian The guardian address to add
    /// @return success True if guardian was added, false if already exists
    function addGuardian(EnumerableMapLib.AddressToUint256Map storage self, address guardian)
        internal
        returns (bool success)
    {
        // Check if guardian already exists
        if (self.contains(guardian)) {
            revert GuardianAlreadyExists();
        }

        return self.set(guardian, uint256(GuardianStatus.REQUESTED));
    }

    /// @notice Remove a guardian completely from the set
    /// @param self The guardian set storage
    /// @param guardian The guardian address to remove
    /// @return success True if guardian was removed, false if not found
    function removeGuardian(EnumerableMapLib.AddressToUint256Map storage self, address guardian)
        internal
        returns (bool success)
    {
        if (!self.contains(guardian)) {
            revert GuardianNotFound();
        }

        return self.remove(guardian);
    }

    /// @notice Update guardian status from REQUESTED to ACCEPTED
    /// @param self The guardian set storage
    /// @param guardian The guardian address to update
    /// @return success True if status was updated successfully
    function acceptGuardian(EnumerableMapLib.AddressToUint256Map storage self, address guardian)
        internal
        returns (bool success)
    {
        if (!self.contains(guardian)) {
            revert GuardianNotFound();
        }

        uint256 currentStatusUint = self.get(guardian);
        GuardianStatus currentStatus = GuardianStatus(currentStatusUint);

        if (currentStatus != GuardianStatus.REQUESTED) {
            revert InvalidStatusTransition();
        }

        return self.set(guardian, uint256(GuardianStatus.ACCEPTED));
    }

    /// @notice Update guardian status (internal function for flexibility)
    /// @param self The guardian set storage
    /// @param guardian The guardian address to update
    /// @param newStatus The new status to set
    /// @return success True if status was updated successfully
    function updateStatus(
        EnumerableMapLib.AddressToUint256Map storage self,
        address guardian,
        GuardianStatus newStatus
    ) internal returns (bool success) {
        if (!self.contains(guardian)) {
            revert GuardianNotFound();
        }

        uint256 currentStatusUint = self.get(guardian);
        GuardianStatus currentStatus = GuardianStatus(currentStatusUint);

        // Validate status transition
        if (!_isValidTransition(currentStatus, newStatus)) {
            revert InvalidStatusTransition();
        }

        return self.set(guardian, uint256(newStatus));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      VIEW FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Get the status of a guardian
    /// @param self The guardian set storage
    /// @param guardian The guardian address to check
    /// @return status The guardian's current status (NONE if not found)
    function getStatus(EnumerableMapLib.AddressToUint256Map storage self, address guardian)
        internal
        view
        returns (GuardianStatus status)
    {
        if (!self.contains(guardian)) {
            return GuardianStatus.NONE;
        }
        return GuardianStatus(self.get(guardian));
    }

    /// @notice Check if a guardian has ACCEPTED status
    /// @param self The guardian set storage
    /// @param guardian The guardian address to check
    /// @return isAccepted True if guardian exists and has ACCEPTED status
    function isAccepted(EnumerableMapLib.AddressToUint256Map storage self, address guardian)
        internal
        view
        returns (bool isAccepted)
    {
        return getStatus(self, guardian) == GuardianStatus.ACCEPTED;
    }

    /// @notice Check if a guardian has REQUESTED status
    /// @param self The guardian set storage
    /// @param guardian The guardian address to check
    /// @return isRequested True if guardian exists and has REQUESTED status
    function isRequested(EnumerableMapLib.AddressToUint256Map storage self, address guardian)
        internal
        view
        returns (bool isRequested)
    {
        return getStatus(self, guardian) == GuardianStatus.REQUESTED;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    INTERNAL HELPERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Validate status transition
    /// @param from Current status
    /// @param to New status
    /// @return isValid True if transition is allowed
    function _isValidTransition(GuardianStatus from, GuardianStatus to)
        private
        pure
        returns (bool isValid)
    {
        // REQUESTED -> ACCEPTED is always valid
        if (from == GuardianStatus.REQUESTED && to == GuardianStatus.ACCEPTED) {
            return true;
        }

        return false;
    }
}
