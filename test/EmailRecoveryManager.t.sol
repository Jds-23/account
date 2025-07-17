// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.23;

// import "./Base.t.sol";
// import {EmailRecoveryManager} from "../src/EmailRecoveryManager.sol";
// import {GuardianManager} from "../src/GuardianManager.sol";
// import {IEmailRecoveryCommandHandler} from "../src/interfaces/IEmailRecoveryCommandHandler.sol";
// import {LibGuardianMap} from "../src/libraries/LibGuardianMap.sol";
// import {LibGuardianConfig, GuardianConfig} from "../src/libraries/LibGuardianConfig.sol";
// import {LibBytes} from "solady/utils/LibBytes.sol";
// import {EnumerableSetLib} from "solady/utils/EnumerableSetLib.sol";
// import {ERC1967Factory} from "solady/utils/ERC1967Factory.sol";

// import {EmailAuth, EmailAuthMsg, EmailProof} from "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";

// contract MockEmailRecoveryCommandHandler is IEmailRecoveryCommandHandler {
//     address public constant RECOVERED_ACCOUNT = address(0xabc);
//     bytes32 public constant RECOVERY_DATA_HASH = keccak256("recovery_data");

//     function acceptanceCommandTemplates()
//         external
//         pure
//         override
//         returns (string[][] memory)
//     {
//         string[][] memory templates = new string[][](1);
//         templates[0] = new string[](5);
//         templates[0][0] = "Accept";
//         templates[0][1] = "guardian";
//         templates[0][2] = "request";
//         templates[0][3] = "for";
//         templates[0][4] = "{ethAddr}";
//         return templates;
//     }

//     function recoveryCommandTemplates()
//         external
//         pure
//         override
//         returns (string[][] memory)
//     {
//         string[][] memory templates = new string[][](1);
//         templates[0] = new string[](5);
//         templates[0][0] = "Recover";
//         templates[0][1] = "account";
//         templates[0][2] = "{ethAddr}";
//         templates[0][3] = "with";
//         templates[0][4] = "{string}";
//         return templates;
//     }

//     function extractRecoveredAccountFromAcceptanceCommand(
//         bytes[] memory /* commandParams */,
//         uint256 /* templateIdx */
//     ) external pure override returns (address) {
//         return RECOVERED_ACCOUNT;
//     }

//     function extractRecoveredAccountFromRecoveryCommand(
//         bytes[] memory /* commandParams */,
//         uint256 /* templateIdx */
//     ) external pure override returns (address) {
//         return RECOVERED_ACCOUNT;
//     }

//     function validateAcceptanceCommand(
//         uint256 /* templateIdx */,
//         bytes[] memory /* commandParams */
//     ) external pure override returns (address) {
//         return RECOVERED_ACCOUNT;
//     }

//     function validateRecoveryCommand(
//         uint256 /* templateIdx */,
//         bytes[] memory /* commandParams */
//     ) external pure override returns (address) {
//         return RECOVERED_ACCOUNT;
//     }

//     function parseRecoveryDataHash(
//         uint256 /* templateIdx */,
//         bytes[] memory /* commandParams */
//     ) external pure override returns (bytes32) {
//         return RECOVERY_DATA_HASH;
//     }
// }

// contract MockEmailAuth {
//     address public controller;

//     constructor(address _controller) {
//         controller = _controller;
//     }

//     function initialize(address, bytes32, address _controller) external {
//         controller = _controller;
//     }

//     function initDKIMRegistry(address) external {}
//     function initVerifier(address) external {}
//     function insertCommandTemplate(uint256, string[] memory) external {}
//     function authEmail(EmailAuthMsg memory) external {}
// }

// contract MockEmailRecoveryManager is EmailRecoveryManager {
//     using LibBytes for LibBytes.BytesStorage;
//     using EnumerableSetLib for EnumerableSetLib.AddressSet;

//     mapping(address => bool) public accountActivated;

//     constructor(
//         address _verifier,
//         address _dkim,
//         address _emailAuthImpl,
//         address _commandHandler,
//         uint128 _minimumDelay,
//         address _factory
//     )
//         EmailRecoveryManager(
//             _verifier,
//             _dkim,
//             _emailAuthImpl,
//             _commandHandler,
//             _minimumDelay,
//             _factory
//         )
//     {}

//     function isActivated(
//         address recoveredAccount
//     ) public view override returns (bool) {
//         return accountActivated[recoveredAccount];
//     }

//     function setActivated(address recoveredAccount, bool _activated) external {
//         accountActivated[recoveredAccount] = _activated;
//     }

//     function acceptanceCommandTemplates()
//         public
//         view
//         override
//         returns (string[][] memory)
//     {
//         return
//             IEmailRecoveryCommandHandler(commandHandler)
//                 .acceptanceCommandTemplates();
//     }

//     function recoveryCommandTemplates()
//         public
//         view
//         override
//         returns (string[][] memory)
//     {
//         return
//             IEmailRecoveryCommandHandler(commandHandler)
//                 .recoveryCommandTemplates();
//     }

//     function extractRecoveredAccountFromAcceptanceCommand(
//         bytes[] memory commandParams,
//         uint256 templateIdx
//     ) public view override returns (address) {
//         return
//             IEmailRecoveryCommandHandler(commandHandler)
//                 .extractRecoveredAccountFromAcceptanceCommand(
//                     commandParams,
//                     templateIdx
//                 );
//     }

//     function extractRecoveredAccountFromRecoveryCommand(
//         bytes[] memory commandParams,
//         uint256 templateIdx
//     ) public view override returns (address) {
//         return
//             IEmailRecoveryCommandHandler(commandHandler)
//                 .extractRecoveredAccountFromRecoveryCommand(
//                     commandParams,
//                     templateIdx
//                 );
//     }

//     function completeRecovery(address, bytes memory) external override {
//         _markRecoveryCompleted();
//     }

//     // Internal function wrappers for testing
//     function _acceptGuardian(
//         address guardian,
//         uint256 templateIdx,
//         bytes[] memory commandParams,
//         bytes32 emailNullifier
//     ) internal override {
//         address account = IEmailRecoveryCommandHandler(commandHandler)
//             .validateAcceptanceCommand(templateIdx, commandParams);

//         RecoveryStorage storage $ = _getRecoveryStorage();
//         if ($.recoveryDataHash[account] != bytes32(0)) {
//             revert RecoveryInProcess();
//         }

//         if (!isActivated(account)) {
//             revert RecoveryIsNotActivated();
//         }

//         uint8 status = getGuardian(account, guardian);
//         if (status != uint8(LibGuardianMap.GuardianStatus.REQUESTED)) {
//             revert GuardianNotRequested();
//         }

//         _updateGuardianStatus(
//             account,
//             guardian,
//             LibGuardianMap.GuardianStatus.ACCEPTED
//         );

//         emit GuardianAccepted(account, guardian);
//     }

//     function _processRecovery(
//         address guardian,
//         uint256 templateIdx,
//         bytes[] memory commandParams,
//         bytes32 emailNullifier
//     ) internal override {
//         address account = IEmailRecoveryCommandHandler(commandHandler)
//             .validateRecoveryCommand(templateIdx, commandParams);

//         if (!isActivated(account)) {
//             revert RecoveryIsNotActivated();
//         }

//         GuardianConfig memory guardianConfig = _getGuardianConfig(account);
//         if (guardianConfig.threshold > guardianConfig.acceptedCount) {
//             revert ThresholdExceedsAcceptedWeight();
//         }

//         uint8 status = getGuardian(account, guardian);
//         if (status != uint8(LibGuardianMap.GuardianStatus.ACCEPTED)) {
//             revert GuardianNotAccepted();
//         }

//         RecoveryStorage storage $ = _getRecoveryStorage();
//         bytes32 recoveryDataHash = IEmailRecoveryCommandHandler(commandHandler)
//             .parseRecoveryDataHash(templateIdx, commandParams);

//         if ($.guardianVotedMapping[account].contains(guardian)) {
//             revert GuardianAlreadyVoted();
//         }

//         bytes32 cachedRecoveryDataHash = $.recoveryDataHash[account];
//         if (cachedRecoveryDataHash == bytes32(0)) {
//             $.recoveryDataHash[account] = recoveryDataHash;
//             $.recoveryRequestTime[account] = uint128(block.timestamp);
//             RecoveryConfig memory recoveryConfig = getRecoveryConfig(account);
//             uint128 expiryTime;
//             unchecked {
//                 expiryTime = uint128(block.timestamp) + recoveryConfig.expiry;
//             }
//             emit RecoveryRequestStarted(
//                 account,
//                 guardian,
//                 expiryTime,
//                 recoveryDataHash
//             );
//         } else if (cachedRecoveryDataHash != recoveryDataHash) {
//             revert InvalidRecoveryDataHash(
//                 recoveryDataHash,
//                 cachedRecoveryDataHash
//             );
//         }

//         $.guardianVotedMapping[account].add(guardian);
//         emit GuardianVoted(account, guardian);

//         if (
//             $.guardianVotedMapping[account].length() >= guardianConfig.threshold
//         ) {
//             emit RecoveryRequestCompleted(account, recoveryDataHash);
//         }
//     }

//     // Test helpers
//     function testConfigureRecovery(
//         address[] calldata guardians,
//         uint8 threshold,
//         uint128 delay,
//         uint128 expiry
//     ) external {
//         configureRecovery(guardians, threshold, delay, expiry);
//     }

//     function testUpdateRecoveryConfig(uint128 delay, uint128 expiry) external {
//         updateRecoveryConfig(delay, expiry);
//     }

//     function getRecoveryDataHash(
//         address account
//     ) external view returns (bytes32) {
//         return _getRecoveryStorage().recoveryDataHash[account];
//     }

//     function getRecoveryRequestTime(
//         address account
//     ) external view returns (uint128) {
//         return _getRecoveryStorage().recoveryRequestTime[account];
//     }

//     function getGuardianVotedCount(
//         address account
//     ) external view returns (uint256) {
//         return _getRecoveryStorage().guardianVotedMapping[account].length();
//     }

//     function isGuardianVoted(
//         address account,
//         address guardian
//     ) external view returns (bool) {
//         return
//             _getRecoveryStorage().guardianVotedMapping[account].contains(
//                 guardian
//             );
//     }
// }

// contract EmailRecoveryManagerTest is BaseTest {
//     using LibBytes for LibBytes.BytesStorage;
//     using EnumerableSetLib for EnumerableSetLib.AddressSet;

//     MockEmailRecoveryManager recoveryManager;
//     MockEmailRecoveryCommandHandler commandHandler;
//     ERC1967Factory factory;
//     MockEmailAuth emailAuthImpl;

//     address verifier = address(0x1);
//     address dkim = address(0x2);
//     uint128 minimumDelay = 1 days;

//     address testAccount = address(0xabc);
//     address[] testGuardians;
//     uint8 testThreshold = 2;
//     uint128 testDelay = 2 days;
//     uint128 testExpiry = 7 days;

//     // Events
//     event RecoveryConfigured(
//         address indexed account,
//         uint256 guardianCount,
//         uint8 threshold
//     );
//     event RecoveryConfigUpdated(
//         address indexed account,
//         uint128 delay,
//         uint128 expiry
//     );
//     event GuardianAccepted(address indexed account, address indexed guardian);
//     event GuardianVoted(address indexed account, address indexed guardian);
//     event RecoveryRequestStarted(
//         address indexed account,
//         address indexed guardian,
//         uint128 expiry,
//         bytes32 recoveryDataHash
//     );
//     event RecoveryRequestCompleted(
//         address indexed account,
//         bytes32 recoveryDataHash
//     );
//     event RecoveryCancelled(address indexed account);
//     event RecoveryCompleted(address indexed account, bytes32 recoveryDataHash);

//     function setUp() public override {
//         super.setUp();

//         commandHandler = new MockEmailRecoveryCommandHandler();
//         factory = new ERC1967Factory();
//         emailAuthImpl = new MockEmailAuth(address(this));

//         recoveryManager = new MockEmailRecoveryManager(
//             verifier,
//             dkim,
//             address(emailAuthImpl),
//             address(commandHandler),
//             minimumDelay,
//             address(factory)
//         );

//         // Setup test guardians
//         testGuardians = new address[](3);
//         testGuardians[0] = address(0x1001);
//         testGuardians[1] = address(0x1002);
//         testGuardians[2] = address(0x1003);

//         // Set account as activated
//         recoveryManager.setActivated(testAccount, true);
//     }

//     ////////////////////////////////////////////////////////////////////////
//     // Constructor Tests
//     ////////////////////////////////////////////////////////////////////////

//     function test_Constructor_Success() public {
//         assertEq(recoveryManager.verifier(), verifier);
//         assertEq(recoveryManager.dkim(), dkim);
//         assertEq(
//             recoveryManager.emailAuthImplementation(),
//             address(emailAuthImpl)
//         );
//         assertEq(recoveryManager.commandHandler(), address(commandHandler));
//         assertEq(recoveryManager.minimumDelay(), minimumDelay);
//         assertEq(address(recoveryManager.factory()), address(factory));
//     }

//     function test_Constructor_RevertIf_InvalidVerifier() public {
//         vm.expectRevert(EmailRecoveryManager.InvalidVerifier.selector);
//         new MockEmailRecoveryManager(
//             address(0),
//             dkim,
//             address(emailAuthImpl),
//             address(commandHandler),
//             minimumDelay,
//             address(factory)
//         );
//     }

//     function test_Constructor_RevertIf_InvalidDkim() public {
//         vm.expectRevert(EmailRecoveryManager.InvalidDkim.selector);
//         new MockEmailRecoveryManager(
//             verifier,
//             address(0),
//             address(emailAuthImpl),
//             address(commandHandler),
//             minimumDelay,
//             address(factory)
//         );
//     }

//     function test_Constructor_RevertIf_InvalidEmailAuthImpl() public {
//         vm.expectRevert(EmailRecoveryManager.InvalidEmailAuthImpl.selector);
//         new MockEmailRecoveryManager(
//             verifier,
//             dkim,
//             address(0),
//             address(commandHandler),
//             minimumDelay,
//             address(factory)
//         );
//     }

//     function test_Constructor_RevertIf_InvalidCommandHandler() public {
//         vm.expectRevert(EmailRecoveryManager.InvalidCommandHandler.selector);
//         new MockEmailRecoveryManager(
//             verifier,
//             dkim,
//             address(emailAuthImpl),
//             address(0),
//             minimumDelay,
//             address(factory)
//         );
//     }

//     function test_Constructor_RevertIf_InvalidFactory() public {
//         vm.expectRevert(EmailRecoveryManager.InvalidFactory.selector);
//         new MockEmailRecoveryManager(
//             verifier,
//             dkim,
//             address(emailAuthImpl),
//             address(commandHandler),
//             minimumDelay,
//             address(0)
//         );
//     }

//     function test_Constructor_RevertIf_InvalidMinimumDelay() public {
//         vm.expectRevert(EmailRecoveryManager.InvalidMinimumDelay.selector);
//         new MockEmailRecoveryManager(
//             verifier,
//             dkim,
//             address(emailAuthImpl),
//             address(commandHandler),
//             0,
//             address(factory)
//         );
//     }

//     ////////////////////////////////////////////////////////////////////////
//     // Configuration Tests
//     ////////////////////////////////////////////////////////////////////////

//     function test_ConfigureRecovery_Success() public {
//         vm.expectEmit(true, false, false, true);
//         emit RecoveryConfigured(
//             testAccount,
//             testGuardians.length,
//             testThreshold
//         );

//         vm.prank(testAccount);
//         recoveryManager.testConfigureRecovery(
//             testGuardians,
//             testThreshold,
//             testDelay,
//             testExpiry
//         );

//         // Check guardian configuration
//         assertEq(recoveryManager.getThreshold(testAccount), testThreshold);

//         // Check recovery configuration
//         EmailRecoveryManager.RecoveryConfig memory config = recoveryManager
//             .getRecoveryConfig(testAccount);
//         assertEq(config.delay, testDelay);
//         assertEq(config.expiry, testExpiry);
//     }

//     function test_ConfigureRecovery_RevertIf_SetupAlreadyCalled() public {
//         vm.prank(testAccount);
//         recoveryManager.testConfigureRecovery(
//             testGuardians,
//             testThreshold,
//             testDelay,
//             testExpiry
//         );

//         vm.expectRevert(EmailRecoveryManager.SetupAlreadyCalled.selector);
//         vm.prank(testAccount);
//         recoveryManager.testConfigureRecovery(
//             testGuardians,
//             testThreshold,
//             testDelay,
//             testExpiry
//         );
//     }

//     function test_UpdateRecoveryConfig_Success() public {
//         vm.prank(testAccount);
//         recoveryManager.testConfigureRecovery(
//             testGuardians,
//             testThreshold,
//             testDelay,
//             testExpiry
//         );

//         uint128 newDelay = 3 days;
//         uint128 newExpiry = 14 days;

//         vm.expectEmit(true, false, false, true);
//         emit RecoveryConfigUpdated(testAccount, newDelay, newExpiry);

//         vm.prank(testAccount);
//         recoveryManager.testUpdateRecoveryConfig(newDelay, newExpiry);

//         EmailRecoveryManager.RecoveryConfig memory config = recoveryManager
//             .getRecoveryConfig(testAccount);
//         assertEq(config.delay, newDelay);
//         assertEq(config.expiry, newExpiry);
//     }

//     function test_UpdateRecoveryConfig_RevertIf_ThresholdNotSet() public {
//         vm.expectRevert(EmailRecoveryManager.ThresholdNotSet.selector);
//         vm.prank(testAccount);
//         recoveryManager.testUpdateRecoveryConfig(testDelay, testExpiry);
//     }

//     function test_UpdateRecoveryConfig_RevertIf_InvalidDelay() public {
//         vm.prank(testAccount);
//         recoveryManager.testConfigureRecovery(
//             testGuardians,
//             testThreshold,
//             testDelay,
//             testExpiry
//         );

//         vm.expectRevert(EmailRecoveryManager.InvalidDelay.selector);
//         vm.prank(testAccount);
//         recoveryManager.testUpdateRecoveryConfig(minimumDelay - 1, testExpiry);
//     }

//     function test_UpdateRecoveryConfig_RevertIf_InvalidExpiry() public {
//         vm.prank(testAccount);
//         recoveryManager.testConfigureRecovery(
//             testGuardians,
//             testThreshold,
//             testDelay,
//             testExpiry
//         );

//         vm.expectRevert(EmailRecoveryManager.InvalidExpiry.selector);
//         vm.prank(testAccount);
//         recoveryManager.testUpdateRecoveryConfig(testExpiry + 1, testExpiry);
//     }

//     ////////////////////////////////////////////////////////////////////////
//     // Compute Address Tests
//     ////////////////////////////////////////////////////////////////////////

//     function test_ComputeEmailAuthAddress_Success() public {
//         bytes32 salt = keccak256("test_salt");
//         address computed = recoveryManager.computeEmailAuthAddress(
//             testAccount,
//             salt
//         );

//         bytes32 expectedSalt = keccak256(abi.encodePacked(testAccount, salt));

//         address expected = factory.predictDeterministicAddress(expectedSalt);
//         assertEq(computed, expected);
//     }

//     ////////////////////////////////////////////////////////////////////////
//     // Template ID Tests
//     ////////////////////////////////////////////////////////////////////////

//     function test_ComputeAcceptanceTemplateId_Success() public {
//         uint256 templateIdx = 0;
//         uint256 templateId = recoveryManager.computeAcceptanceTemplateId(
//             templateIdx
//         );

//         uint256 expected = uint256(
//             keccak256(abi.encode(1, "ACCEPTANCE", templateIdx))
//         );
//         assertEq(templateId, expected);
//     }

//     function test_ComputeRecoveryTemplateId_Success() public {
//         uint256 templateIdx = 0;
//         uint256 templateId = recoveryManager.computeRecoveryTemplateId(
//             templateIdx
//         );

//         uint256 expected = uint256(
//             keccak256(abi.encode(1, "RECOVERY", templateIdx))
//         );
//         assertEq(templateId, expected);
//     }

//     ////////////////////////////////////////////////////////////////////////
//     // Guardian Acceptance Tests
//     ////////////////////////////////////////////////////////////////////////

//     function test_HandleAcceptance_Success() public {
//         // Setup recovery configuration
//         vm.prank(testAccount);
//         recoveryManager.testConfigureRecovery(
//             testGuardians,
//             testThreshold,
//             testDelay,
//             testExpiry
//         );

//         // Create mock email auth message
//         EmailAuthMsg memory emailAuthMsg = _createMockEmailAuthMsg(0, true);

//         vm.expectEmit(true, true, false, false);
//         emit GuardianAccepted(testAccount, testGuardians[0]);

//         recoveryManager.handleAcceptance(emailAuthMsg, 0);

//         // Check guardian status
//         uint8 status = recoveryManager.getGuardian(
//             testAccount,
//             testGuardians[0]
//         );
//         assertEq(status, uint8(LibGuardianMap.GuardianStatus.ACCEPTED));
//     }

//     function test_HandleAcceptance_RevertIf_InvalidAccountInEmail() public {
//         EmailAuthMsg memory emailAuthMsg = _createMockEmailAuthMsg(0, true);

//         // Mock the command handler to return zero address
//         vm.mockCall(
//             address(commandHandler),
//             abi.encodeWithSelector(
//                 IEmailRecoveryCommandHandler
//                     .extractRecoveredAccountFromAcceptanceCommand
//                     .selector
//             ),
//             abi.encode(address(0))
//         );

//         vm.expectRevert(EmailRecoveryManager.InvalidAccountInEmail.selector);
//         recoveryManager.handleAcceptance(emailAuthMsg, 0);
//     }

//     function test_HandleAcceptance_RevertIf_InvalidTemplateId() public {
//         EmailAuthMsg memory emailAuthMsg = _createMockEmailAuthMsg(0, true);
//         emailAuthMsg.templateId = 999; // Wrong template ID

//         vm.expectRevert(EmailRecoveryManager.InvalidTemplateId.selector);
//         recoveryManager.handleAcceptance(emailAuthMsg, 0);
//     }

//     function test_HandleAcceptance_RevertIf_IsCodeExistFalse() public {
//         EmailAuthMsg memory emailAuthMsg = _createMockEmailAuthMsg(0, false);

//         vm.expectRevert(EmailRecoveryManager.IsCodeExistFalse.selector);
//         recoveryManager.handleAcceptance(emailAuthMsg, 0);
//     }

//     ////////////////////////////////////////////////////////////////////////
//     // Recovery Process Tests
//     ////////////////////////////////////////////////////////////////////////

//     function test_HandleRecovery_Success() public {
//         // Setup and accept guardians
//         _setupAndAcceptGuardians();

//         // Create mock email auth message
//         EmailAuthMsg memory emailAuthMsg = _createMockEmailAuthMsg(0, true);
//         emailAuthMsg.templateId = recoveryManager.computeRecoveryTemplateId(0);

//         // Deploy mock email auth for guardian
//         address guardianAddress = recoveryManager.computeEmailAuthAddress(
//             testAccount,
//             emailAuthMsg.proof.accountSalt
//         );
//         vm.etch(guardianAddress, type(MockEmailAuth).creationCode);
//         MockEmailAuth(guardianAddress).initialize(
//             address(0),
//             bytes32(0),
//             address(recoveryManager)
//         );

//         vm.expectEmit(true, true, false, false);
//         emit GuardianVoted(testAccount, testGuardians[0]);

//         recoveryManager.handleRecovery(emailAuthMsg, 0);

//         // Check guardian voted
//         assertTrue(
//             recoveryManager.isGuardianVoted(testAccount, testGuardians[0])
//         );
//     }

//     function test_HandleRecovery_RevertIf_GuardianNotDeployed() public {
//         _setupAndAcceptGuardians();

//         EmailAuthMsg memory emailAuthMsg = _createMockEmailAuthMsg(0, true);
//         emailAuthMsg.templateId = recoveryManager.computeRecoveryTemplateId(0);

//         vm.expectRevert(EmailRecoveryManager.GuardianNotDeployed.selector);
//         recoveryManager.handleRecovery(emailAuthMsg, 0);
//     }

//     function test_RecoveryProcess_ThresholdReached() public {
//         _setupAndAcceptGuardians();

//         // First guardian vote
//         _mockGuardianVote(testGuardians[0]);

//         // Second guardian vote - should trigger completion
//         vm.expectEmit(true, false, false, true);
//         emit RecoveryRequestCompleted(
//             testAccount,
//             commandHandler.RECOVERY_DATA_HASH()
//         );

//         _mockGuardianVote(testGuardians[1]);

//         // Check voting count
//         assertEq(recoveryManager.getGuardianVotedCount(testAccount), 2);
//     }

//     ////////////////////////////////////////////////////////////////////////
//     // Recovery Cancellation Tests
//     ////////////////////////////////////////////////////////////////////////

//     function test_CancelRecovery_Success() public {
//         _setupAndAcceptGuardians();
//         _mockGuardianVote(testGuardians[0]);

//         // Verify recovery is in process
//         assertNotEq(
//             recoveryManager.getRecoveryDataHash(testAccount),
//             bytes32(0)
//         );

//         vm.expectEmit(true, false, false, false);
//         emit RecoveryCancelled(testAccount);

//         vm.prank(testAccount);
//         recoveryManager.cancelRecovery();

//         // Verify recovery is cancelled
//         assertEq(recoveryManager.getRecoveryDataHash(testAccount), bytes32(0));
//         assertEq(recoveryManager.getRecoveryRequestTime(testAccount), 0);
//         assertEq(recoveryManager.getGuardianVotedCount(testAccount), 0);
//     }

//     function test_CancelRecovery_RevertIf_RecoveryNotInProgress() public {
//         _setupAndAcceptGuardians();

//         vm.expectRevert(EmailRecoveryManager.RecoveryNotInProgress.selector);
//         vm.prank(testAccount);
//         recoveryManager.cancelRecovery();
//     }

//     ////////////////////////////////////////////////////////////////////////
//     // Recovery Completion Tests
//     ////////////////////////////////////////////////////////////////////////

//     function test_CompleteRecovery_Success() public {
//         _setupAndAcceptGuardians();
//         _mockGuardianVote(testGuardians[0]);
//         _mockGuardianVote(testGuardians[1]);

//         bytes32 recoveryDataHash = recoveryManager.getRecoveryDataHash(
//             testAccount
//         );

//         vm.expectEmit(true, false, false, true);
//         emit RecoveryCompleted(testAccount, recoveryDataHash);

//         vm.prank(testAccount);
//         recoveryManager.completeRecovery(testAccount, "");

//         // Verify recovery is completed
//         assertEq(recoveryManager.getRecoveryDataHash(testAccount), bytes32(0));
//         assertEq(recoveryManager.getRecoveryRequestTime(testAccount), 0);
//         assertEq(recoveryManager.getGuardianVotedCount(testAccount), 0);
//     }

//     ////////////////////////////////////////////////////////////////////////
//     // Fuzz Tests
//     ////////////////////////////////////////////////////////////////////////

//     function testFuzz_ComputeEmailAuthAddress_ConsistentResults(
//         address account,
//         bytes32 salt
//     ) public {
//         vm.assume(account != address(0));

//         address computed1 = recoveryManager.computeEmailAuthAddress(
//             account,
//             salt
//         );
//         address computed2 = recoveryManager.computeEmailAuthAddress(
//             account,
//             salt
//         );

//         assertEq(computed1, computed2);
//     }

//     ////////////////////////////////////////////////////////////////////////
//     // Helper Functions
//     ////////////////////////////////////////////////////////////////////////

//     function _createMockEmailAuthMsg(
//         uint256 guardianIdx,
//         bool isCodeExist
//     ) internal view returns (EmailAuthMsg memory) {
//         EmailAuthMsg memory authMsg;
//         authMsg.templateId = recoveryManager.computeAcceptanceTemplateId(0);
//         authMsg.commandParams = new bytes[](1);
//         authMsg.commandParams[0] = abi.encode(testAccount);

//         authMsg.proof.accountSalt = keccak256(
//             abi.encode(testGuardians[guardianIdx])
//         );
//         authMsg.proof.isCodeExist = isCodeExist;
//         authMsg.proof.emailNullifier = keccak256("nullifier");

//         return authMsg;
//     }

//     function _setupAndAcceptGuardians() internal {
//         vm.prank(testAccount);
//         recoveryManager.testConfigureRecovery(
//             testGuardians,
//             testThreshold,
//             testDelay,
//             testExpiry
//         );

//         // Accept all guardians
//         for (uint256 i = 0; i < testGuardians.length; i++) {
//             _mockGuardianAcceptance(testGuardians[i]);
//         }
//     }

//     function _mockGuardianAcceptance(address guardian) internal {
//         EmailAuthMsg memory emailAuthMsg = EmailAuthMsg({
//             templateId: recoveryManager.computeAcceptanceTemplateId(0),
//             commandParams: new bytes[](1),
//             proof: EmailProof({
//                 accountSalt: keccak256(abi.encode(guardian)),
//                 isCodeExist: true,
//                 emailNullifier: keccak256("nullifier")
//             })
//         });

//         recoveryManager.handleAcceptance(emailAuthMsg, 0);
//     }

//     function _mockGuardianVote(address guardian) internal {
//         EmailAuthMsg memory emailAuthMsg = EmailAuthMsg({
//             templateId: recoveryManager.computeRecoveryTemplateId(0),
//             commandParams: new bytes[](1),
//             proof: EmailProof({
//                 accountSalt: keccak256(abi.encode(guardian)),
//                 isCodeExist: true,
//                 emailNullifier: keccak256("nullifier")
//             })
//         });

//         address guardianAddress = recoveryManager.computeEmailAuthAddress(
//             testAccount,
//             emailAuthMsg.proof.accountSalt
//         );
//         vm.etch(guardianAddress, type(MockEmailAuth).creationCode);
//         MockEmailAuth(guardianAddress).initialize(
//             address(0),
//             bytes32(0),
//             address(recoveryManager)
//         );

//         recoveryManager.handleRecovery(emailAuthMsg, 0);
//     }
// }
