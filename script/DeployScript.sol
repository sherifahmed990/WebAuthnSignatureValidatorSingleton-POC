// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {WebAuthnSignatureValidatorSingleton} from "../src/WebAuthnSignatureValidatorSingleton.sol";
import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";

contract DeterministicDeployScript is Script {
    //https://github.com/Zoltu/deterministic-deployment-proxy/blob/master/source/deterministic-deployment-proxy.yul
    address internal constant DETERMINISTIC_CREATE2_FACTORY = 0x7A0D94F55792C434d74a40883C6ed8545E406D12;
    address internal constant EXPECTED_ADDRESS = 0xcA66C5A0eEAb0Fe74F343bb4A539042c68aE45F9;

    function run() public 
    returns (WebAuthnSignatureValidatorSingleton webAuthnSigner){
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        bytes memory returnData;
        bool success;

        if(!isContract(EXPECTED_ADDRESS)){ //check if already deployed
            bytes memory webAuthnSignatureValidatorSingletonCreationCode = abi.encodePacked(
                type(WebAuthnSignatureValidatorSingleton).creationCode, 
                abi.encode(0xCAc51aDF726E4b269645a7fD6a43296A1Ff53e8d)
            );

            (success, returnData) = DETERMINISTIC_CREATE2_FACTORY.call(
                webAuthnSignatureValidatorSingletonCreationCode);
            webAuthnSigner = WebAuthnSignatureValidatorSingleton(address(uint160(bytes20(returnData))));

            assert(address(webAuthnSigner) == EXPECTED_ADDRESS);
        }
        vm.stopBroadcast();
    }

    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}
