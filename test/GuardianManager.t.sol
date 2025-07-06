// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Base.t.sol";
import {GuardianManager} from "../src/GuardianManager.sol";
import {LibGuardianMap} from "../src/libraries/LibGuardianMap.sol";
import {LibGuardianConfig} from "../src/libraries/LibGuardianConfig.sol";
import {LibBytes} from "solady/utils/LibBytes.sol";
import {EnumerableMapLib} from "solady/utils/EnumerableMapLib.sol";
import {Vm} from "forge-std/Vm.sol";

contract MockGuardianManager is GuardianManager {
    using LibBytes for LibBytes.BytesStorage;
    using EnumerableMapLib for EnumerableMapLib.AddressToUint256Map;
    using LibGuardianMap for EnumerableMapLib.AddressToUint256Map;
    using LibGuardianConfig for LibBytes.BytesStorage;

    function setupGuardians(
        address account,
        address[] calldata guardians,
        uint8 threshold
    ) external {
        _setupGuardians(account, guardians, threshold);
    }

    function addGuardian(address account, address guardian) external {
        _addGuardian(account, guardian);
    }

    function removeGuardian(address account, address guardian) external {
        _removeGuardian(account, guardian);
    }

    function changeThreshold(address account, uint8 threshold) external {
        _changeThreshold(account, threshold);
    }

    function updateGuardianStatus(
        address account,
        address guardian,
        LibGuardianMap.GuardianStatus newStatus
    ) external {
        _updateGuardianStatus(account, guardian, newStatus);
    }

    function getGuardianStorageSlot() external view returns (uint256 slot) {
        GuardianStorage storage $ = _getGuardianStorage();
        assembly {
            slot := $.slot
        }
    }

    function getGuardianConfig(
        address account
    )
        external
        view
        returns (uint8 guardianCount, uint8 acceptedCount, uint8 threshold)
    {
        GuardianStorage storage $ = _getGuardianStorage();
        guardianCount = LibGuardianConfig.getGuardianCount(
            $.accountGuardiansConfig[account]
        );
        acceptedCount = LibGuardianConfig.getAcceptedCount(
            $.accountGuardiansConfig[account]
        );
        threshold = LibGuardianConfig.getThreshold(
            $.accountGuardiansConfig[account]
        );
    }

    function getGuardianStatus(
        address account,
        address guardian
    ) external view returns (LibGuardianMap.GuardianStatus) {
        GuardianStorage storage $ = _getGuardianStorage();
        return LibGuardianMap.getStatus($.accountGuardians[account], guardian);
    }

    function isGuardianAccepted(
        address account,
        address guardian
    ) external view returns (bool) {
        GuardianStorage storage $ = _getGuardianStorage();
        return LibGuardianMap.isAccepted($.accountGuardians[account], guardian);
    }

    function getGuardianCount(address account) external view returns (uint8) {
        GuardianStorage storage $ = _getGuardianStorage();
        return uint8($.accountGuardians[account].length());
    }
}

contract GuardianManagerTest is BaseTest {
    using LibBytes for LibBytes.BytesStorage;
    using EnumerableMapLib for EnumerableMapLib.AddressToUint256Map;

    MockGuardianManager guardianManager;
    address testAccount;
    address[] testGuardians;
    uint8 testThreshold;

    // Events from GuardianManager
    event GuardianAdded(address indexed account, address indexed guardian);
    event GuardianRemoved(address indexed account, address indexed guardian);
    event GuardianStatusChanged(
        address indexed account,
        address indexed guardian,
        LibGuardianMap.GuardianStatus status
    );
    event ThresholdChanged(address indexed account, uint8 threshold);

    function setUp() public override {
        super.setUp();
        guardianManager = new MockGuardianManager();
        testAccount = address(0xabc);
        testThreshold = 2;

        // Setup test guardians
        testGuardians = new address[](3);
        testGuardians[0] = address(0x1);
        testGuardians[1] = address(0x2);
        testGuardians[2] = address(0x3);
    }

    function test_SetupGuardians_Success() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        (
            uint8 guardianCount,
            uint8 acceptedCount,
            uint8 threshold
        ) = guardianManager.getGuardianConfig(testAccount);

        assertEq(guardianCount, 3);
        assertEq(acceptedCount, 0);
        assertEq(threshold, 2);

        // Check all guardians are in REQUESTED status
        for (uint256 i = 0; i < testGuardians.length; i++) {
            LibGuardianMap.GuardianStatus status = guardianManager
                .getGuardianStatus(testAccount, testGuardians[i]);
            assertEq(
                uint8(status),
                uint8(LibGuardianMap.GuardianStatus.REQUESTED)
            );
        }
    }

    function test_SetupGuardians_EmitsEvents() public {
        vm.recordLogs();

        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();

        // Should emit exactly 3 GuardianAdded events
        assertEq(logs.length, 3);

        // Check each event
        for (uint256 i = 0; i < 3; i++) {
            assertEq(
                logs[i].topics[0],
                keccak256("GuardianAdded(address,address)")
            );
            assertEq(address(uint160(uint256(logs[i].topics[1]))), testAccount);
            assertEq(abi.decode(logs[i].data, (address)), testGuardians[i]);
        }
    }

    function test_SetupGuardians_RevertIf_GuardianAlreadyExists() public {
        address[] memory duplicateGuardians = new address[](2);
        duplicateGuardians[0] = testGuardians[0];
        duplicateGuardians[1] = testGuardians[0]; // duplicate

        vm.expectRevert(LibGuardianMap.GuardianAlreadyExists.selector);
        guardianManager.setupGuardians(testAccount, duplicateGuardians, 1);
    }

    function test_SetupGuardians_RevertIf_InvalidGuardian_ZeroAddress() public {
        address[] memory invalidGuardians = new address[](1);
        invalidGuardians[0] = address(0);

        vm.expectRevert(GuardianManager.InvalidGuardian.selector);
        guardianManager.setupGuardians(testAccount, invalidGuardians, 1);
    }

    function test_SetupGuardians_RevertIf_InvalidGuardian_SelfAddress() public {
        address[] memory selfGuardians = new address[](1);
        selfGuardians[0] = testAccount;

        vm.expectRevert(GuardianManager.InvalidGuardian.selector);
        guardianManager.setupGuardians(testAccount, selfGuardians, 1);
    }

    function test_SetupGuardians_RevertIf_InvalidThreshold_Zero() public {
        vm.expectRevert(LibGuardianConfig.InvalidThreshold.selector);
        guardianManager.setupGuardians(testAccount, testGuardians, 0);
    }

    function test_SetupGuardians_RevertIf_InvalidThreshold_TooHigh() public {
        vm.expectRevert(LibGuardianConfig.InvalidThreshold.selector);
        guardianManager.setupGuardians(testAccount, testGuardians, 4);
    }

    function test_SetupGuardians_RevertIf_TooManyGuardians() public {
        address[] memory tooManyGuardians = new address[](33);
        for (uint256 i = 0; i < 33; i++) {
            tooManyGuardians[i] = address(uint160(i + 1));
        }

        vm.expectRevert(LibGuardianConfig.MaxGuardiansExceeded.selector);
        guardianManager.setupGuardians(testAccount, tooManyGuardians, 16);
    }

    function test_AddGuardian_Success() public {
        address newGuardian = address(0x4);

        vm.recordLogs();
        guardianManager.addGuardian(testAccount, newGuardian);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(
            logs[0].topics[0],
            keccak256("GuardianAdded(address,address)")
        );
        assertEq(address(uint160(uint256(logs[0].topics[1]))), testAccount);
        assertEq(abi.decode(logs[0].data, (address)), newGuardian);

        LibGuardianMap.GuardianStatus status = guardianManager
            .getGuardianStatus(testAccount, newGuardian);
        assertEq(uint8(status), uint8(LibGuardianMap.GuardianStatus.REQUESTED));
    }

    function test_AddGuardian_RevertIf_GuardianAlreadyExists() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        vm.expectRevert(LibGuardianMap.GuardianAlreadyExists.selector);
        guardianManager.addGuardian(testAccount, testGuardians[0]);
    }

    function test_AddGuardian_RevertIf_InvalidGuardian_ZeroAddress() public {
        vm.expectRevert(GuardianManager.InvalidGuardian.selector);
        guardianManager.addGuardian(testAccount, address(0));
    }

    function test_AddGuardian_RevertIf_InvalidGuardian_SelfAddress() public {
        vm.expectRevert(GuardianManager.InvalidGuardian.selector);
        guardianManager.addGuardian(testAccount, testAccount);
    }

    function test_RemoveGuardian_Success() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        vm.recordLogs();
        guardianManager.removeGuardian(testAccount, testGuardians[0]);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(
            logs[0].topics[0],
            keccak256("GuardianRemoved(address,address)")
        );
        assertEq(address(uint160(uint256(logs[0].topics[1]))), testAccount);
        assertEq(
            address(uint160(uint256(logs[0].topics[2]))),
            testGuardians[0]
        );

        LibGuardianMap.GuardianStatus status = guardianManager
            .getGuardianStatus(testAccount, testGuardians[0]);
        assertEq(uint8(status), uint8(LibGuardianMap.GuardianStatus.NONE));

        (uint8 guardianCount, , ) = guardianManager.getGuardianConfig(
            testAccount
        );
        assertEq(guardianCount, 2);
    }

    function test_RemoveGuardian_AcceptedGuardian() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        // Accept a guardian first
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.ACCEPTED
        );

        (
            uint8 guardianCount,
            uint8 acceptedCount,
            uint8 threshold
        ) = guardianManager.getGuardianConfig(testAccount);
        assertEq(guardianCount, 3);
        assertEq(acceptedCount, 1);
        assertEq(threshold, 2);

        // Check guardian is indeed accepted
        assertTrue(
            guardianManager.isGuardianAccepted(testAccount, testGuardians[0])
        );

        // Remove the accepted guardian
        guardianManager.removeGuardian(testAccount, testGuardians[0]);

        (guardianCount, acceptedCount, threshold) = guardianManager
            .getGuardianConfig(testAccount);
        assertEq(guardianCount, 2);
        assertEq(acceptedCount, 0);
        assertEq(threshold, 2); // Threshold are not changed
    }

    function test_ChangeThreshold_Success() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        // Accept guardians to enable threshold change
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.ACCEPTED
        );
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[1],
            LibGuardianMap.GuardianStatus.ACCEPTED
        );

        uint8 newThreshold = 1;

        vm.expectEmit(true, false, false, true);
        emit ThresholdChanged(testAccount, newThreshold);

        guardianManager.changeThreshold(testAccount, newThreshold);

        (, , uint8 threshold) = guardianManager.getGuardianConfig(testAccount);
        assertEq(threshold, newThreshold);
    }

    function test_UpdateGuardianStatus_RequestedToAccepted() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        vm.expectEmit(true, true, false, true);
        emit GuardianStatusChanged(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.ACCEPTED
        );

        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.ACCEPTED
        );

        LibGuardianMap.GuardianStatus status = guardianManager
            .getGuardianStatus(testAccount, testGuardians[0]);
        assertEq(uint8(status), uint8(LibGuardianMap.GuardianStatus.ACCEPTED));

        assertTrue(
            guardianManager.isGuardianAccepted(testAccount, testGuardians[0])
        );
    }

    function test_UpdateGuardianStatus_RevertIf_AcceptedToRequested() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        // First accept
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.ACCEPTED
        );

        // Then try to revert to requested - should fail
        vm.expectRevert(LibGuardianMap.InvalidStatusTransition.selector);
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.REQUESTED
        );
    }

    function test_UpdateGuardianStatus_RevertIf_RequestedToNone() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        // Try to set status to NONE - should fail
        vm.expectRevert(LibGuardianMap.InvalidStatusTransition.selector);
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.NONE
        );
    }

    function test_UpdateGuardianStatus_RevertIf_AcceptedToNone() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        // First accept
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.ACCEPTED
        );

        // Try to set status to NONE - should fail
        vm.expectRevert(LibGuardianMap.InvalidStatusTransition.selector);
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.NONE
        );
    }

    function test_UpdateGuardianStatus_RevertIf_RequestedToRequested() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        // Try to set status to same status (REQUESTED) - should fail
        vm.expectRevert(LibGuardianMap.InvalidStatusTransition.selector);
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.REQUESTED
        );
    }

    function test_UpdateGuardianStatus_RevertIf_AcceptedToAccepted() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        // First accept
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.ACCEPTED
        );

        // Try to set status to same status (ACCEPTED) - should fail
        vm.expectRevert(LibGuardianMap.InvalidStatusTransition.selector);
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.ACCEPTED
        );
    }

    function test_UpdateGuardianStatus_RevertIf_GuardianNotAdded() public {
        address nonExistentGuardian = address(0x999);

        vm.expectRevert(GuardianManager.GuardianNotAdded.selector);
        guardianManager.updateGuardianStatus(
            testAccount,
            nonExistentGuardian,
            LibGuardianMap.GuardianStatus.ACCEPTED
        );
    }

    function test_GuardianStoragePointer_ConsistentAccess() public {
        // Test that the storage pointer is consistent across calls
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );

        (uint8 guardianCount1, , ) = guardianManager.getGuardianConfig(
            testAccount
        );
        (uint8 guardianCount2, , ) = guardianManager.getGuardianConfig(
            testAccount
        );

        assertEq(guardianCount1, guardianCount2);
        assertEq(guardianCount1, 3);
    }

    function test_MaxGuardiansLimit() public {
        // Test exactly at the limit
        address[] memory maxGuardians = new address[](32);
        for (uint256 i = 0; i < 32; i++) {
            maxGuardians[i] = address(uint160(i + 1));
        }

        guardianManager.setupGuardians(testAccount, maxGuardians, 16);

        (uint8 guardianCount, , ) = guardianManager.getGuardianConfig(
            testAccount
        );
        assertEq(guardianCount, 32);
    }

    // Fuzz Tests
    function testFuzz_SetupGuardians_ValidInputs(
        address account,
        uint8 numGuardians,
        uint8 threshold
    ) public {
        vm.assume(account != address(0));
        vm.assume(numGuardians > 0 && numGuardians <= 32);
        vm.assume(threshold > 0 && threshold <= numGuardians);

        address[] memory guardians = new address[](numGuardians);
        for (uint256 i = 0; i < numGuardians; i++) {
            guardians[i] = address(uint160(i + 1));
            vm.assume(guardians[i] != account);
        }

        guardianManager.setupGuardians(account, guardians, threshold);

        (
            uint8 guardianCount,
            uint8 acceptedCount,
            uint8 thresholdStored
        ) = guardianManager.getGuardianConfig(account);

        assertEq(guardianCount, numGuardians);
        assertEq(acceptedCount, 0);
        assertEq(thresholdStored, threshold);
    }

    function testFuzz_AddGuardian_ValidInputs(
        address account,
        address guardian
    ) public {
        vm.assume(account != address(0));
        vm.assume(guardian != address(0));
        vm.assume(account != guardian);

        guardianManager.addGuardian(account, guardian);

        LibGuardianMap.GuardianStatus status = guardianManager
            .getGuardianStatus(account, guardian);
        assertEq(uint8(status), uint8(LibGuardianMap.GuardianStatus.REQUESTED));
    }

    function testFuzz_UpdateGuardianStatus_ValidTransitions(
        address account,
        address guardian
    ) public {
        vm.assume(account != address(0));
        vm.assume(guardian != address(0));
        vm.assume(account != guardian);

        guardianManager.addGuardian(account, guardian);

        // Only test REQUESTED -> ACCEPTED transition (the only valid one)
        guardianManager.updateGuardianStatus(
            account,
            guardian,
            LibGuardianMap.GuardianStatus.ACCEPTED
        );

        LibGuardianMap.GuardianStatus status = guardianManager
            .getGuardianStatus(account, guardian);
        assertEq(uint8(status), uint8(LibGuardianMap.GuardianStatus.ACCEPTED));
    }

    function testFuzz_MultipleGuardians_Operations(
        address account,
        uint8 numGuardians,
        uint8 threshold,
        uint8 numToAccept
    ) public {
        vm.assume(account != address(0));
        vm.assume(numGuardians > 0 && numGuardians <= 10); // Limit for fuzz efficiency
        vm.assume(threshold > 0 && threshold <= numGuardians);
        vm.assume(numToAccept <= numGuardians);

        address[] memory guardians = new address[](numGuardians);
        for (uint256 i = 0; i < numGuardians; i++) {
            guardians[i] = address(uint160(i + 1));
            vm.assume(guardians[i] != account);
        }

        guardianManager.setupGuardians(account, guardians, threshold);

        // Accept some guardians
        for (uint256 i = 0; i < numToAccept; i++) {
            guardianManager.updateGuardianStatus(
                account,
                guardians[i],
                LibGuardianMap.GuardianStatus.ACCEPTED
            );
        }

        // Verify counts
        (
            uint8 guardianCount,
            uint8 acceptedCount,
            uint8 thresholdStored
        ) = guardianManager.getGuardianConfig(account);

        assertEq(guardianCount, numGuardians);
        assertEq(acceptedCount, numToAccept);
        assertEq(thresholdStored, threshold);

        // Verify individual statuses
        for (uint256 i = 0; i < numGuardians; i++) {
            LibGuardianMap.GuardianStatus expectedStatus = i < numToAccept
                ? LibGuardianMap.GuardianStatus.ACCEPTED
                : LibGuardianMap.GuardianStatus.REQUESTED;

            LibGuardianMap.GuardianStatus actualStatus = guardianManager
                .getGuardianStatus(account, guardians[i]);
            assertEq(uint8(actualStatus), uint8(expectedStatus));
        }
    }

    // Edge Case Tests
    function test_EdgeCase_RemoveLastGuardian() public {
        address[] memory singleGuardian = new address[](1);
        singleGuardian[0] = address(0x1);

        guardianManager.setupGuardians(testAccount, singleGuardian, 1);
        guardianManager.changeThreshold(testAccount, 0);
        guardianManager.removeGuardian(testAccount, singleGuardian[0]);

        (uint8 guardianCount, , ) = guardianManager.getGuardianConfig(
            testAccount
        );
        assertEq(guardianCount, 0);
    }

    function test_EdgeCase_StatusChangeAfterRemoval() public {
        guardianManager.setupGuardians(
            testAccount,
            testGuardians,
            testThreshold
        );
        guardianManager.removeGuardian(testAccount, testGuardians[0]);

        // Should revert when trying to update status of removed guardian
        vm.expectRevert(GuardianManager.GuardianNotAdded.selector);
        guardianManager.updateGuardianStatus(
            testAccount,
            testGuardians[0],
            LibGuardianMap.GuardianStatus.ACCEPTED
        );
    }

    function test_EdgeCase_MultipleAccountsIndependence() public {
        address account1 = address(0x100);
        address account2 = address(0x200);

        guardianManager.setupGuardians(account1, testGuardians, testThreshold);

        address[] memory differentGuardians = new address[](2);
        differentGuardians[0] = address(0x4);
        differentGuardians[1] = address(0x5);

        guardianManager.setupGuardians(account2, differentGuardians, 1);

        // Verify accounts are independent
        (uint8 count1, , ) = guardianManager.getGuardianConfig(account1);
        (uint8 count2, , ) = guardianManager.getGuardianConfig(account2);

        assertEq(count1, 3);
        assertEq(count2, 2);

        // Guardian from account1 should not exist in account2
        LibGuardianMap.GuardianStatus status = guardianManager
            .getGuardianStatus(account2, testGuardians[0]);
        assertEq(uint8(status), uint8(LibGuardianMap.GuardianStatus.NONE));
    }
}
