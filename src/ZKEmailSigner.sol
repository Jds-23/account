// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IIthacaAccount} from "./interfaces/IIthacaAccount.sol";
import {ISigner} from "./interfaces/ISigner.sol";

/// @title ZKEmailSigner
/// @notice A Signer contract, that extends ZK-email functionality to the Porto Account.
abstract contract ZKEmailSigner is ISigner {
    ////////////////////////////////////////////////////////////////////////
    // Constants
    ////////////////////////////////////////////////////////////////////////

    /// @dev The magic value returned by `isValidSignatureWithKeyHash` when the signature is valid.
    bytes4 internal constant _MAGIC_VALUE = 0x1626ba7e;

    /// @dev The magic value returned by `isValidSignatureWithKeyHash` when the signature is invalid.
    bytes4 internal constant _FAIL_VALUE = 0xffffffff;

    ////////////////////////////////////////////////////////////////////////
    // State Variables
    ////////////////////////////////////////////////////////////////////////
}
