// SPDX-License-Identifier: LGPL-3.0-only
/* solhint-disable one-contract-per-file */
pragma solidity >=0.8.0;

import {SignatureValidator} from "./SignatureValidator.sol";
import {IWebAuthnVerifier, WebAuthnConstants} from "./verifiers/WebAuthnVerifier.sol";

struct SignatureData {
    bytes authenticatorData;
    bytes clientDataFields;
    uint256[2] rs;
}

/**
 * @title WebAuthnSignatureValidator
 * @dev A contract that represents a WebAuthn signer.
 */
contract WebAuthnSignatureValidator is SignatureValidator {
    address internal singleton;
    uint256 public X;
    uint256 public Y;
    IWebAuthnVerifier public WEBAUTHN_SIG_VERIFIER;

    // This constructor ensures that this contract can only be used as a singleton for Proxy contracts
    constructor() {
        /**
         * By setting the X and Y it is not possible to call setup anymore,
         * This is an unusable validator, perfect for the singleton
         */
        X = 1;
        Y = 1;
    }

    /**
     * @dev setup function.
     * @param x The X coordinate of the signer's public key.
     * @param y The Y coordinate of the signer's public key.
     * @param webAuthnVerifier The address of the P256Verifier contract.
     */
    function setup(uint256 x, uint256 y, address webAuthnVerifier) external {
        if (X > 0 || Y > 0 || address(WEBAUTHN_SIG_VERIFIER) > address(0)) revert('WebAuthnSignatureValidator have already been set up');
        X = x;
        Y = y;
        WEBAUTHN_SIG_VERIFIER = IWebAuthnVerifier(webAuthnVerifier);
    }

    /**
     * @inheritdoc SignatureValidator
     */
    function _verifySignature(bytes32 message, bytes calldata signature) internal view virtual override returns (bool isValid) {
        SignatureData calldata signaturePointer;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            signaturePointer := signature.offset
        }

        return
            WEBAUTHN_SIG_VERIFIER.verifyWebAuthnSignatureAllowMalleability(
                signaturePointer.authenticatorData,
                WebAuthnConstants.AUTH_DATA_FLAGS_UV,
                message,
                signaturePointer.clientDataFields,
                signaturePointer.rs,
                X,
                Y
            );
    }
}
