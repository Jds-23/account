// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {LibBytes} from "solady/utils/LibBytes.sol";
/// @note need handle cases where, initialy threshold > acceptedCount. So removal of accepted guardian will cause underflow.
/// let's consider acceptedCount can be < threshold

/// @title LibGuardianConfig
/// @notice Helper library for managing guardian configurations using optimized byte storage
/// @dev Uses LibBytes for gas-efficient storage of guardian data
library LibGuardianConfig {
    using LibBytes for LibBytes.BytesStorage;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Maximum number of guardians allowed
    uint8 internal constant MAX_GUARDIANS = 32;

    /// @dev Byte indices for packed data
    uint256 internal constant GUARDIAN_COUNT_INDEX = 0;
    uint256 internal constant ACCEPTED_COUNT_INDEX = 1;
    uint256 internal constant THRESHOLD_INDEX = 2;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ERRORS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error MaxGuardiansExceeded();
    error InvalidThreshold();
    error GuardianCountUnderflow();
    error AcceptedCountExceedsTotal();
    error AcceptedCountUnderflow();
    error ThresholdExceedsAccepted();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    STORAGE OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // @notice Initialize guardian configuration with zero accepted guardians
    /// @param self The bytes storage to write to
    /// @param guardianCount Total number of guardians to configure
    /// @param threshold Minimum guardians required for consensus (must be 0 when acceptedCount is 0)
    function initConfig(LibBytes.BytesStorage storage self, uint8 guardianCount, uint8 threshold)
        internal
    {
        // Validate configuration
        if (guardianCount > MAX_GUARDIANS) revert MaxGuardiansExceeded();
        if (threshold == 0 || threshold > guardianCount) {
            revert InvalidThreshold();
        }

        self.set(
            abi.encodePacked(
                guardianCount,
                uint8(0), // acceptedCount = 0
                threshold
            )
        );
    }

    // /// @notice Load guardian configuration from storage
    // /// @param self The bytes storage to read from
    // /// @return config The unpacked guardian configuration
    // function loadConfig(
    //     LibBytes.BytesStorage storage self
    // ) internal view returns (GuardianConfig memory config) {
    //     if (self.isEmpty()) {
    //         return GuardianConfig(0, 0, 0, 0);
    //     }

    //     config.guardianCount = self.uint8At(GUARDIAN_COUNT_INDEX);
    //     config.acceptedCount = self.uint8At(ACCEPTED_COUNT_INDEX);
    //     config.threshold = self.uint8At(THRESHOLD_INDEX);
    //     config.reserved = 0; // Always 0 for now
    // }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   GUARDIAN COUNT OPERATIONS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Increment the guardian count
    /// @param self The bytes storage to modify
    function incrementGuardianCount(LibBytes.BytesStorage storage self) internal {
        uint8 currentCount = self.uint8At(GUARDIAN_COUNT_INDEX);
        if (currentCount >= MAX_GUARDIANS) revert MaxGuardiansExceeded();

        _updateByteAt(self, GUARDIAN_COUNT_INDEX, currentCount + 1);
    }

    /// @notice Following functions are expensive af but will be fixed

    /// @notice Decrement the guardian count
    /// @param self The bytes storage to modify
    function decrementGuardianCount(LibBytes.BytesStorage storage self) internal {
        uint8 currentCount = self.uint8At(GUARDIAN_COUNT_INDEX);
        if (currentCount == 0) revert GuardianCountUnderflow();

        uint8 newCount = currentCount - 1;
        uint8 acceptedCount = self.uint8At(ACCEPTED_COUNT_INDEX);
        uint8 threshold = self.uint8At(THRESHOLD_INDEX);

        if (newCount < acceptedCount || newCount < threshold) {
            revert GuardianCountUnderflow();
        }

        _updateByteAt(self, GUARDIAN_COUNT_INDEX, newCount);
    }

    /// @notice Increment the accepted guardian count
    /// @param self The bytes storage to modify
    function incrementAcceptedCount(LibBytes.BytesStorage storage self) internal {
        uint8 currentAccepted = self.uint8At(ACCEPTED_COUNT_INDEX);
        uint8 totalGuardians = self.uint8At(GUARDIAN_COUNT_INDEX);

        if (currentAccepted >= totalGuardians) {
            revert AcceptedCountExceedsTotal();
        }

        _updateByteAt(self, ACCEPTED_COUNT_INDEX, currentAccepted + 1);
    }

    /// @notice Decrement the accepted guardian count
    /// @param self The bytes storage to modify
    function decrementAcceptedCount(LibBytes.BytesStorage storage self) internal {
        uint8 currentAccepted = self.uint8At(ACCEPTED_COUNT_INDEX);
        if (currentAccepted == 0) revert AcceptedCountUnderflow();

        uint8 newAccepted = currentAccepted - 1;

        _updateByteAt(self, ACCEPTED_COUNT_INDEX, newAccepted);
    }

    /// @notice Set the threshold for guardian consensus
    /// @param self The bytes storage to modify
    /// @param threshold The new threshold value
    function setThreshold(LibBytes.BytesStorage storage self, uint8 threshold) internal {
        uint8 acceptedCount = self.uint8At(ACCEPTED_COUNT_INDEX);

        if (threshold == 0 && acceptedCount > 0) revert InvalidThreshold();
        if (threshold > acceptedCount) revert ThresholdExceedsAccepted();

        _updateByteAt(self, THRESHOLD_INDEX, threshold);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      VIEW FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Get the current guardian count
    /// @param self The bytes storage to read from
    /// @return The number of guardians
    function getGuardianCount(LibBytes.BytesStorage storage self) internal view returns (uint8) {
        return self.uint8At(GUARDIAN_COUNT_INDEX);
    }

    /// @notice Get the current accepted guardian count
    /// @param self The bytes storage to read from
    /// @return The number of accepted guardians
    function getAcceptedCount(LibBytes.BytesStorage storage self) internal view returns (uint8) {
        return self.uint8At(ACCEPTED_COUNT_INDEX);
    }

    /// @notice Get the current threshold
    /// @param self The bytes storage to read from
    /// @return The threshold value
    function getThreshold(LibBytes.BytesStorage storage self) internal view returns (uint8) {
        return self.uint8At(THRESHOLD_INDEX);
    }

    /// @notice Check if the threshold is met given a number of confirmations
    /// @param self The bytes storage to read from
    /// @param confirmations Number of guardian confirmations
    /// @return Whether the threshold is met
    function isThresholdMet(LibBytes.BytesStorage storage self, uint8 confirmations)
        internal
        view
        returns (bool)
    {
        uint8 threshold = self.uint8At(THRESHOLD_INDEX);
        return confirmations >= threshold && threshold > 0;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PRIVATE HELPERS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Update a single byte at the specified index
    /// @param self The bytes storage to modify
    /// @param index The byte index to update
    /// @param value The new byte value
    function _updateByteAt(LibBytes.BytesStorage storage self, uint256 index, uint8 value)
        private
    {
        // Get current data
        bytes memory currentData = self.get();

        // Ensure we have enough bytes
        if (currentData.length <= index) {
            // Extend the array if needed
            bytes memory newData = new bytes(index + 1);
            for (uint256 i = 0; i < currentData.length; i++) {
                newData[i] = currentData[i];
            }
            newData[index] = bytes1(value);
            self.set(newData);
        } else {
            // Update existing byte
            currentData[index] = bytes1(value);
            self.set(currentData);
        }
    }
}
