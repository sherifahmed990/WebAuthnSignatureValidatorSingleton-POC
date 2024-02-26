// SPDX-License-Identifier: LGPL-3.0-only
/* solhint-disable one-contract-per-file */
pragma solidity >=0.8.0;

import {SignatureValidator} from "./SignatureValidator.sol";
import {IWebAuthnVerifier, WebAuthnConstants} from "./verifiers/WebAuthnVerifier.sol";
import {ISafe} from "./interfaces/ISafe.sol";

struct SignatureData {
    bytes authenticatorData;
    bytes clientDataFields;
    uint256[2] rs;
}

/**
 * @title WebAuthnSignatureValidatorSingleton
 * @dev A contract that verifies a WebAuthn signature.
 * https://github.com/safe-global/safe-modules/blob/main/modules/4337/contracts/experimental/WebAuthnSingletonSigner.sol
 */
contract WebAuthnSignatureValidatorSingleton is SignatureValidator {
    IWebAuthnVerifier public immutable WEBAUTHN_SIG_VERIFIER;
    address private immutable SIGNATURE_VALIDATOR_SINGLETON;
    bytes32 private immutable SLOT_X;
    bytes32 private immutable SLOT_Y;

    /**
     * @dev Constructor function.
     * @param webAuthnVerifier The address of the P256Verifier contract.
     */
    constructor(address webAuthnVerifier) {
        WEBAUTHN_SIG_VERIFIER = IWebAuthnVerifier(webAuthnVerifier);
        SIGNATURE_VALIDATOR_SINGLETON = address(this);
        SLOT_X = bytes32(uint256(uint160(SIGNATURE_VALIDATOR_SINGLETON)));
        SLOT_Y = bytes32(uint256(SLOT_X)+1);
    }

    /**
     * @inheritdoc SignatureValidator
     */
    function _verifySignature(bytes32 message, bytes calldata signature) internal view virtual override returns (bool isValid) {
        uint256 X;
        uint256 Y;
        SignatureData calldata signaturePointer;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            signaturePointer := signature.offset
        }

        (X, Y) = abi.decode(
            ISafe(msg.sender).getStorageAt(uint256(SLOT_X), 2),
            (uint256, uint256)
        );

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

    /*
     *@dev to be delegate called from the Safe account
     */
    function setSigner(uint256 X, uint256 Y) public {
        require(address(this) != SIGNATURE_VALIDATOR_SINGLETON, "setSigner should only be called via delegatecall");

        bytes32 slotX = SLOT_X;
        bytes32 slotY = SLOT_Y;
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slotX, X)
            sstore(slotY, Y)
        }
    }

    /*
     *@dev to be delegate called from the Safe account
     */
    function removeSigner() public {
        require(address(this) != SIGNATURE_VALIDATOR_SINGLETON, "removeSigner should only be called via delegatecall");
        require(!ISafe(address(this)).isOwner(SIGNATURE_VALIDATOR_SINGLETON), "can't clear the signer storage before removing the validator singleton from the owners list");

        bytes32 slotX = SLOT_X;
        bytes32 slotY = SLOT_Y;
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slotX, 0)
            sstore(slotY, 0)
        }
    }
}
