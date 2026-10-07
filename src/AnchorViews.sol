// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IdentityRegistry.sol";
import "./AuthConfigManager.sol";

contract AnchorViews {
    IdentityRegistry public immutable IDENTITY_REGISTRY;
    AuthConfigManager public immutable AUTH_CONFIG_MANAGER;

    struct AuthenticatorView {
        uint8 id;
        AuthConfigManager.Scheme scheme;
        bytes32 identityId;
        address owner;
        string displayName;
        bool active;
    }

    struct AccountSummary {
        uint64 configVersion;
        AuthenticatorView[] authenticators;
        uint8[] signingPolicy;
        uint8 signingThreshold;
        uint8[] reconfigPolicy;
        uint8 reconfigThreshold;
        bool hasPending;
        uint64 pendingProposedAt;
        uint64 pendingActivatesAt;
        uint8 pendingRiskScore;
        bool pendingRequiresExtraConfirmation;
        bool pendingExtraConfirmationGiven;
        uint64 nextNonce;
    }

    constructor(
        address identityRegistry,
        address authConfigManager
    ) {
        IDENTITY_REGISTRY = IdentityRegistry(identityRegistry);
        AUTH_CONFIG_MANAGER = AuthConfigManager(authConfigManager);
    }

    function getAccountSummary(
        address account
    ) external view returns (AccountSummary memory summary) {
        AuthConfigManager.AuthConfig memory cfg =
            AUTH_CONFIG_MANAGER.getConfig(account);

        AuthConfigManager.PendingReconfig memory pending =
            AUTH_CONFIG_MANAGER.getPendingReconfig(account);

        summary.configVersion = cfg.configVersion;
        summary.signingPolicy = cfg.signingPolicy;
        summary.signingThreshold = cfg.signingThreshold;
        summary.reconfigPolicy = cfg.reconfigPolicy;
        summary.reconfigThreshold = cfg.reconfigThreshold;
        summary.nextNonce = AUTH_CONFIG_MANAGER.actionNonce(account);

        summary.authenticators =
            new AuthenticatorView[](cfg.authenticators.length);

        for (uint256 i = 0; i < cfg.authenticators.length; i++) {
            AuthConfigManager.Authenticator memory a =
                cfg.authenticators[i];

            IdentityRegistry.Identity memory idy =
                IDENTITY_REGISTRY.getIdentity(a.identityId);

            summary.authenticators[i] = AuthenticatorView({
                id: a.id,
                scheme: a.scheme,
                identityId: a.identityId,
                owner: idy.owner,
                displayName: idy.displayName,
                active: idy.active
            });
        }

        summary.hasPending = pending.exists;

        if (pending.exists) {
            summary.pendingProposedAt =
                pending.proposedAt;

            summary.pendingActivatesAt =
                pending.proposedAt +
                AUTH_CONFIG_MANAGER.RECONFIG_DELAY();

            summary.pendingRiskScore =
                pending.riskScore;

            summary.pendingRequiresExtraConfirmation =
                pending.requiresExtraConfirmation;

            summary.pendingExtraConfirmationGiven =
                pending.extraConfirmationGiven;
        }
    }

    function isInitialized(
        address account
    ) external view returns (bool) {
        return AUTH_CONFIG_MANAGER.getConfigVersion(account) > 0;
    }

    function needsAttention(
        address account
    ) external view returns (bool) {
        AuthConfigManager.PendingReconfig memory pending =
            AUTH_CONFIG_MANAGER.getPendingReconfig(account);

        return pending.exists;
    }
}
