// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ICommon} from "../interfaces/ICommon.sol";
import {ERC7821} from "solady/accounts/ERC7821.sol";

/// @title IIthacaAccount
/// @notice Interface for the Account contract
interface IIthacaAccount is ICommon {
    /// @dev Pays `paymentAmount` of `paymentToken` to the `paymentRecipient`.
    /// @param keyHash The hash of the key used to authorize the operation
    /// @param encodedIntent The encoded user operation
    /// @param intentDigest The digest of the user operation
    function pay(
        uint256 paymentAmount,
        bytes32 keyHash,
        bytes32 intentDigest,
        bytes calldata encodedIntent
    ) external;

    /// @dev Returns if the signature is valid, along with its `keyHash`.
    /// The `signature` is a wrapped signature, given by
    /// `abi.encodePacked(bytes(innerSignature), bytes32(keyHash), bool(prehash))`.
    function unwrapAndValidateSignature(bytes32 digest, bytes calldata signature)
        external
        view
        returns (bool isValid, bytes32 keyHash);

    /// @dev Return current nonce with sequence key.
    function getNonce(uint192 seqKey) external view returns (uint256 nonce);

    /// @dev Return the key hash that signed the latest execution context.
    /// @dev Returns bytes32(0) if the EOA key was used.
    function getContextKeyHash() external view returns (bytes32);

    /// @dev Check and increment the nonce.
    function checkAndIncrementNonce(uint256 nonce) external payable;

    /// @dev Computes the EIP712 digest for `calls`.
    /// If the the nonce starts with `MULTICHAIN_NONCE_PREFIX`,
    /// the digest will be computed without the chain ID.
    /// Otherwise, the digest will be computed with the chain ID.
    function computeDigest(ERC7821.Call[] calldata calls, uint256 nonce)
        external
        view
        returns (bytes32 result);
}
