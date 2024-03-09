// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {WebAuthnSignatureValidatorSingleton} from "../src/WebAuthnSignatureValidatorSingleton.sol";
import {WebAuthnSignatureValidator} from "../src/WebAuthnSignatureValidator.sol";
import {WebAuthnSignatureValidatorProxy} from "../src/WebAuthnSignatureValidatorProxy.sol";
import {WebAuthnSignatureValidatorProxyFactory} from "../src/WebAuthnSignatureValidatorProxyFactory.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

contract DeterministicDeployScript is Script {
    //https://github.com/Zoltu/deterministic-deployment-proxy/blob/master/source/deterministic-deployment-proxy.yul
    address internal constant DETERMINISTIC_CREATE2_FACTORY = 0x7A0D94F55792C434d74a40883C6ed8545E406D12;
    address internal constant WEB_AUTHN_VERIFIER = 0xCAc51aDF726E4b269645a7fD6a43296A1Ff53e8d;
    address internal constant SIGNATURE_VALIDATOR_SINGLETON_EXPECTED_ADDRESS = 0xcA66C5A0eEAb0Fe74F343bb4A539042c68aE45F9;
    address internal constant SIGNATURE_VALIDATOR_EXPECTED_ADDRESS = 0x21e4747c7215fe6e343376034f08261bbd9ac497;
    address internal constant SIGNATURE_VALIDATOR_PROXY_EXPECTED_ADDRESS = 0x5476a503d35445b4203065b3F957281746Af3EfC;
    address internal constant SIGNATURE_VALIDATOR_PROXY_FACTORY_EXPECTED_ADDRESS = 0xEae2AD611c0e8E14604B8cc611a89d5e9d138B49;

    function run() public 
    returns (
        WebAuthnSignatureValidatorSingleton webAuthnSigner, 
        WebAuthnSignatureValidator signatureValidator,
        WebAuthnSignatureValidatorProxy signatureValidatorProxy,
        WebAuthnSignatureValidatorProxyFactory signatureValidatorProxyFactory
    ){
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        bytes memory returnData;
        bool success;

        if(!isContract(SIGNATURE_VALIDATOR_SINGLETON_EXPECTED_ADDRESS)){ //check if already deployed
            bytes memory signatureValidatorSingletonCreationCode = abi.encodePacked(
            type(WebAuthnSignatureValidatorSingleton).creationCode, abi.encode(WEB_AUTHN_VERIFIER));

            (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(
                signatureValidatorSingletonCreationCode);
            webAuthnSigner = WebAuthnSignatureValidatorSingleton(address(uint160(bytes20(returnData))));

            assert(address(webAuthnSigner) == SIGNATURE_VALIDATOR_SINGLETON_EXPECTED_ADDRESS);
        }

        if(!isContract(SIGNATURE_VALIDATOR_EXPECTED_ADDRESS)){ //check if already deployed
            bytes memory signatureValidatorCreationCode = abi.encodePacked(
            type(WebAuthnSignatureValidator).creationCode);

            (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(
                signatureValidatorCreationCode);
            signatureValidator = WebAuthnSignatureValidator(payable(address(uint160(bytes20(returnData)))));

            assert(address(signatureValidator) == SIGNATURE_VALIDATOR_EXPECTED_ADDRESS);
        }

        if(!isContract(SIGNATURE_VALIDATOR_PROXY_EXPECTED_ADDRESS)){ //check if already deployed
            bytes memory signatureValidatorProxyCreationCode = abi.encodePacked(
            type(WebAuthnSignatureValidatorProxy).creationCode, abi.encode(SIGNATURE_VALIDATOR_EXPECTED_ADDRESS));

            (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(
                signatureValidatorProxyCreationCode);
            signatureValidatorProxy = WebAuthnSignatureValidatorProxy(payable(address(uint160(bytes20(returnData)))));

            assert(address(signatureValidatorProxy) == SIGNATURE_VALIDATOR_PROXY_EXPECTED_ADDRESS);
        }


        if(!isContract(SIGNATURE_VALIDATOR_PROXY_FACTORY_EXPECTED_ADDRESS)){ //check if already deployed
            bytes memory signatureValidatorProxyFactoryCreationCode = abi.encodePacked(
            type(WebAuthnSignatureValidatorProxyFactory).creationCode);

            (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(
                signatureValidatorProxyFactoryCreationCode);
            signatureValidatorProxyFactory = WebAuthnSignatureValidatorProxyFactory(payable(address(uint160(bytes20(returnData)))));

            assert(address(signatureValidatorProxyFactory) == SIGNATURE_VALIDATOR_PROXY_FACTORY_EXPECTED_ADDRESS);
        }

        vm.stopBroadcast();
    }

    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}
