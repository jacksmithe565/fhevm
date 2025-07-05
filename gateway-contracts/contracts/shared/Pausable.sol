// SPDX-License-Identifier: BSD-3-Clause-Clear
pragma solidity ^0.8.24;

import { gatewayConfigAddress } from "../../addresses/GatewayConfigAddress.sol";
import { Ownable2StepUpgradeable } from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "../interfaces/IGatewayConfig.sol";

abstract contract Pausable is Ownable2StepUpgradeable, PausableUpgradeable {
    IGatewayConfig private constant _GATEWAY_CONFIG = IGatewayConfig(gatewayConfigAddress);

    error NotOwnerOrPauser(address notOwnerOrPauser);

    function pause() external virtual {
        if (msg.sender != owner() && msg.sender != _GATEWAY_CONFIG.getPauser()) revert NotOwnerOrPauser(msg.sender);
        _pause();
    }

    function unpause() external virtual onlyOwner {
        _unpause();
    }
}
