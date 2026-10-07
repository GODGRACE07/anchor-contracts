// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./IdentityRegistry.sol";
import "./RiskScoring.sol";
import "./P256Verifier.sol";
import "./WebAuthnVerifier.sol";

contract AuthConfigManager {
    IdentityRegistry public immutable IDENTITY_REGISTRY;

    uint64 public constant RECONFIG_DELAY = 24 hours;
    uint64 public constant TRANSFER_DELAY = 1 hours;

    enum Scheme {
        SECP256K1,
        P256_PASSKEY,
        GUARDIAN,
        AGENT
    }

    struct Authenticator {
        uint8 id;
        Scheme scheme;
        bytes32 identityId;
    }

    struct AuthConfig {
        Authenticator[] authenticators;
        uint8[] signingPolicy;
        uint8 signingThreshold;
        uint8[] reconfigPolicy;
        uint8 reconfigThreshold;
        uint64 configVersion;
    }

    struct PendingReconfig {
        Authenticator[] authenticators;
        uint8[] signingPolicy;
        uint8 signingThreshold;
        uint8[] reconfigPolicy;
        uint8 reconfigThreshold;
        uint64 proposedAt;
        bool exists;
        uint8 riskScore;
        bool requiresExtraConfirmation;
        bool extraConfirmationGiven;
    }

    struct AuthProof {
        uint8 authenticatorId;
        bytes32 sigR;
        bytes32 sigS;
    }

    struct WebAuthnAuthProof {
        uint8 authenticatorId;
        WebAuthnVerifier.WebAuthnProof proof;
    }

    struct PasskeyReconfigConfig {
        Authenticator[] authenticators;
        uint8[] signingPolicy;
        uint8 signingThreshold;
        uint8[] reconfigPolicy;
        uint8 reconfigThreshold;
        bool isKnownDevicePattern;
    }


    struct PendingTransfer {
        address to;
        uint256 amount;
        uint64 proposedAt;
        bool exists;
    }

    mapping(address => AuthConfig) internal accountConfigs;
    mapping(address => PendingReconfig) internal pendingConfigs;
    mapping(address => uint64) public lastActivityAt;
    mapping(address => uint32) public recentFailedAttempts;
    mapping(address => uint64) public actionNonce;
    mapping(address => uint256) public accountBalance;
    mapping(address => mapping(address => bool)) public knownDestination;
    mapping(address => PendingTransfer) public pendingTransfers;

    event ConfigInitialized(
        address indexed account,
        uint64 configVersion
    );

    event ReconfigurationProposed(
        address indexed account,
        uint64 currentVersion,
        uint64 proposedAt,
        uint8 riskScore
    );

    event ReconfigurationContested(
        address indexed account,
        uint64 contestedAt
    );

    event ReconfigurationActivated(
        address indexed account,
        uint64 newVersion
    );

    event ExtraConfirmationGiven(address indexed account);

    event FundsReceived(
        address indexed account,
        uint256 amount
    );

    event VerifiedTransferExecuted(
        address indexed account,
        address indexed to,
        uint256 amount,
        uint64 nonce
    );

    event TransferProposed(
        address indexed account,
        address indexed to,
        uint256 amount,
        uint64 proposedAt
    );

    event TransferContested(
        address indexed account,
        address indexed to,
        uint64 contestedAt
    );

    event NewDestinationTransferActivated(
        address indexed account,
        address indexed to,
        uint256 amount
    );

    constructor(address identityRegistry) {
        IDENTITY_REGISTRY = IdentityRegistry(identityRegistry);
    }

    // ---------- Views ----------

    function getConfig(
        address account
    ) external view returns (AuthConfig memory) {
        return accountConfigs[account];
    }

    function getConfigVersion(
        address account
    ) external view returns (uint64) {
        return accountConfigs[account].configVersion;
    }

    function getPendingReconfig(
        address account
    ) external view returns (PendingReconfig memory) {
        return pendingConfigs[account];
    }

    // ---------- Internal signature-threshold verification ----------

    function _actionMessageHash(
        address account,
        string memory action,
        uint64 nonce
    ) internal pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                "Anchor:",
                action,
                ":",
                account,
                ":",
                nonce
            )
        );
    }

    function _findAuthenticator(
        Authenticator[] storage list,
        uint8 id
    ) internal view returns (Authenticator storage) {
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i].id == id) {
                return list[i];
            }
        }

        revert("Authenticator id not found in policy");
    }

    function _validateConfigInputs(
        Authenticator[] memory authenticators,
        uint8[] memory signingPolicy,
        uint8[] memory reconfigPolicy
    ) internal pure {
        // Every authenticator ID must be unique and every identity may
        // only appear once. Otherwise one key could occupy multiple
        // threshold slots.
        for (uint256 i = 0; i < authenticators.length; i++) {
            for (uint256 j = i + 1; j < authenticators.length; j++) {
                require(
                    authenticators[i].id != authenticators[j].id,
                    "Duplicate authenticator id"
                );

                require(
                    authenticators[i].identityId != authenticators[j].identityId,
                    "Duplicate authenticator identity"
                );
            }
        }

        // Every policy entry must reference a configured authenticator,
        // and each authenticator may appear only once per policy.
        for (uint256 i = 0; i < signingPolicy.length; i++) {
            bool found = false;

            for (uint256 j = 0; j < authenticators.length; j++) {
                if (authenticators[j].id == signingPolicy[i]) {
                    found = true;
                    break;
                }
            }

            require(found, "Signing policy authenticator not found");

            for (uint256 j = i + 1; j < signingPolicy.length; j++) {
                require(
                    signingPolicy[i] != signingPolicy[j],
                    "Duplicate signing policy id"
                );
            }
        }

        for (uint256 i = 0; i < reconfigPolicy.length; i++) {
            bool found = false;

            for (uint256 j = 0; j < authenticators.length; j++) {
                if (authenticators[j].id == reconfigPolicy[i]) {
                    found = true;
                    break;
                }
            }

            require(found, "Reconfig policy authenticator not found");

            for (uint256 j = i + 1; j < reconfigPolicy.length; j++) {
                require(
                    reconfigPolicy[i] != reconfigPolicy[j],
                    "Duplicate reconfig policy id"
                );
            }
        }
    }

    function _verifyThreshold(
        address account,
        uint8[] storage policyIds,
        uint8 threshold,
        bytes32 messageHash,
        AuthProof[] calldata proofs
    ) internal view {
        require(proofs.length > 0, "No proofs supplied");

        bool[] memory usedProofSlots = new bool[](proofs.length);
        uint8 satisfied = 0;

        for (
            uint256 p = 0;
            p < policyIds.length && satisfied < threshold;
            p++
        ) {
            uint8 policyId = policyIds[p];

            for (uint256 i = 0; i < proofs.length; i++) {
                if (
                    usedProofSlots[i] ||
                    proofs[i].authenticatorId != policyId
                ) {
                    continue;
                }

                Authenticator storage authr =
                    _findAuthenticator(
                        accountConfigs[account].authenticators,
                        policyId
                    );

                IdentityRegistry.Identity memory idy =
                    IDENTITY_REGISTRY.getIdentity(authr.identityId);

                require(
                    idy.active,
                    "Authenticator identity inactive"
                );

                require(
                    idy.owner == account,
                    "Authenticator identity owner mismatch"
                );

                bool ok = P256Verifier.verify(
                    messageHash,
                    proofs[i].sigR,
                    proofs[i].sigS,
                    idy.pubKeyX,
                    idy.pubKeyY
                );

                if (ok) {
                    usedProofSlots[i] = true;
                    satisfied += 1;
                    break;
                }
            }
        }

        require(
            satisfied >= threshold,
            "Threshold not satisfied"
        );
    }

    function _verifyWebAuthnThreshold(
        address account,
        uint8[] storage policyIds,
        uint8 threshold,
        bytes32 expectedChallenge,
        WebAuthnAuthProof[] memory proofs
    ) internal view {
        require(proofs.length > 0, "No proofs supplied");

        bool[] memory usedProofSlots =
            new bool[](proofs.length);

        uint8 satisfied = 0;

        for (
            uint256 p = 0;
            p < policyIds.length && satisfied < threshold;
            p++
        ) {
            uint8 policyId = policyIds[p];

            for (uint256 i = 0; i < proofs.length; i++) {
                if (
                    usedProofSlots[i] ||
                    proofs[i].authenticatorId != policyId
                ) {
                    continue;
                }

                Authenticator storage authr =
                    _findAuthenticator(
                        accountConfigs[account].authenticators,
                        policyId
                    );

                require(
                    authr.scheme == Scheme.P256_PASSKEY,
                    "Authenticator is not a passkey"
                );

                IdentityRegistry.Identity memory idy =
                    IDENTITY_REGISTRY.getIdentity(
                        authr.identityId
                    );

                require(
                    idy.active,
                    "Authenticator identity inactive"
                );

                require(
                    idy.owner == account,
                    "Authenticator identity owner mismatch"
                );

                bool ok =
                    WebAuthnVerifier.verify(
                        proofs[i].proof,
                        expectedChallenge,
                        idy.pubKeyX,
                        idy.pubKeyY
                    );

                if (ok) {
                    usedProofSlots[i] = true;
                    satisfied += 1;
                    break;
                }
            }
        }

        require(
            satisfied >= threshold,
            "Threshold not satisfied"
        );
    }

    // ---------- Config / reconfiguration ----------

    function initializeConfig(
        Authenticator[] calldata authenticators,
        uint8[] calldata signingPolicy,
        uint8 signingThreshold,
        uint8[] calldata reconfigPolicy,
        uint8 reconfigThreshold
    ) external {
        require(
            accountConfigs[msg.sender].configVersion == 0,
            "Already initialized"
        );

        require(
            authenticators.length > 0,
            "Need at least one authenticator"
        );

        require(
            signingThreshold > 0 &&
            signingThreshold <= signingPolicy.length,
            "Invalid signing threshold"
        );

        require(
            reconfigThreshold > 0 &&
            reconfigThreshold <= reconfigPolicy.length,
            "Invalid reconfig threshold"
        );

        _validateConfigInputs(
            authenticators,
            signingPolicy,
            reconfigPolicy
        );

        AuthConfig storage cfg = accountConfigs[msg.sender];

        for (uint256 i = 0; i < authenticators.length; i++) {
            cfg.authenticators.push(authenticators[i]);
        }

        for (uint256 i = 0; i < signingPolicy.length; i++) {
            cfg.signingPolicy.push(signingPolicy[i]);
        }

        for (uint256 i = 0; i < reconfigPolicy.length; i++) {
            cfg.reconfigPolicy.push(reconfigPolicy[i]);
        }

        cfg.signingThreshold = signingThreshold;
        cfg.reconfigThreshold = reconfigThreshold;
        cfg.configVersion = 1;

        lastActivityAt[msg.sender] =
            uint64(block.timestamp);

        emit ConfigInitialized(msg.sender, 1);
    }

    struct ReconfigInput {
        Authenticator[] authenticators;
        uint8[] signingPolicy;
        uint8 signingThreshold;
        uint8[] reconfigPolicy;
        uint8 reconfigThreshold;
        bool isKnownDevicePattern;
    }

    function proposeReconfiguration(
        address account,
        ReconfigInput calldata config,
        AuthProof[] calldata proofs
    ) external {
        require(
            accountConfigs[account].configVersion > 0,
            "Not initialized"
        );
        require(
            config.authenticators.length > 0,
            "Need at least one authenticator"
        );
        require(
            config.signingThreshold > 0 &&
            config.signingThreshold <= config.signingPolicy.length,
            "Invalid signing threshold"
        );
        require(
            config.reconfigThreshold > 0 &&
            config.reconfigThreshold <= config.reconfigPolicy.length,
            "Invalid reconfig threshold"
        );

        _validateConfigInputs(
            config.authenticators,
            config.signingPolicy,
            config.reconfigPolicy
        );

        {
            uint64 nonce = actionNonce[account];
            bytes32 msgHash = _actionMessageHash(account, "propose", nonce);

            _verifyThreshold(
                account,
                accountConfigs[account].reconfigPolicy,
                accountConfigs[account].reconfigThreshold,
                msgHash,
                proofs
            );

            actionNonce[account] = nonce + 1;
        }

        uint8 riskScore = _computeReconfigRisk(
            account,
            config.authenticators.length,
            config.reconfigThreshold,
            config.isKnownDevicePattern
        );

        delete pendingConfigs[account];

        PendingReconfig storage pending = pendingConfigs[account];

        for (uint256 i = 0; i < config.authenticators.length; i++) {
            pending.authenticators.push(config.authenticators[i]);
        }
        for (uint256 i = 0; i < config.signingPolicy.length; i++) {
            pending.signingPolicy.push(config.signingPolicy[i]);
        }
        for (uint256 i = 0; i < config.reconfigPolicy.length; i++) {
            pending.reconfigPolicy.push(config.reconfigPolicy[i]);
        }

        pending.signingThreshold = config.signingThreshold;
        pending.reconfigThreshold = config.reconfigThreshold;
        pending.proposedAt = uint64(block.timestamp);
        pending.exists = true;
        pending.riskScore = riskScore;
        pending.requiresExtraConfirmation = RiskScoring.isHighRisk(riskScore);
        pending.extraConfirmationGiven = false;

        emit ReconfigurationProposed(
            account,
            accountConfigs[account].configVersion,
            pending.proposedAt,
            riskScore
        );
    }

    function _computeReconfigRisk(
        address account,
        uint256 newAuthenticatorCount,
        uint8 newReconfigThreshold,
        bool isKnownDevicePattern
    ) internal view returns (uint8) {
        return RiskScoring.computeRiskScore(
            RiskScoring.AttemptContext({
                timestamp: uint64(block.timestamp),
                timeSinceLastActivity:
                    uint64(block.timestamp) - lastActivityAt[account],
                isKnownDevicePattern: isKnownDevicePattern,
                recentFailedAttempts: recentFailedAttempts[account],
                thresholdWeakened:
                    newReconfigThreshold <
                    accountConfigs[account].reconfigThreshold,
                authenticatorsRemoved:
                    newAuthenticatorCount <
                    accountConfigs[account].authenticators.length
            })
        );
    }

    /// @notice Propose a reconfiguration using WebAuthn/passkey proofs.
    ///
    /// The payload is ABI encoded as:
    /// (
    ///     address account,
    ///     Authenticator[] authenticators,
    ///     uint8[] signingPolicy,
    ///     uint8 signingThreshold,
    ///     uint8[] reconfigPolicy,
    ///     uint8 reconfigThreshold,
    ///     bool isKnownDevicePattern,
    ///     WebAuthnAuthProof[] proofs
    /// )
    ///
    /// The individual fields are decoded by small helper functions so the
    /// generated IR does not keep all dynamic values on the stack together.
    /// @dev Wire format for proposeReconfigurationWithPasskey:
    ///      abi.encode(PasskeyReconfigRequest(account, config, proofs))
    struct PasskeyReconfigRequest {
        address account;
        PasskeyReconfigConfig config;
        WebAuthnAuthProof[] proofs;
    }

    function proposeReconfigurationWithPasskey(
        bytes calldata requestData
    ) external {
        PasskeyReconfigRequest memory req =
            abi.decode(requestData, (PasskeyReconfigRequest));

        _proposeReconfigurationWithPasskey(
            req.account,
            req.config,
            req.proofs
        );
    }

    function _proposeReconfigurationWithPasskey(
        address account,
        PasskeyReconfigConfig memory config,
        WebAuthnAuthProof[] memory proofs
    ) internal {
        _validateConfigInputs(
            config.authenticators,
            config.signingPolicy,
            config.reconfigPolicy
        );

        require(
            accountConfigs[account].configVersion > 0,
            "Not initialized"
        );

        require(
            config.authenticators.length > 0,
            "Need at least one authenticator"
        );

        require(
            config.signingThreshold > 0 &&
            config.signingThreshold <= config.signingPolicy.length,
            "Invalid signing threshold"
        );

        require(
            config.reconfigThreshold > 0 &&
            config.reconfigThreshold <= config.reconfigPolicy.length,
            "Invalid reconfig threshold"
        );

        uint64 nonce = actionNonce[account];

        bytes32 challenge =
            _actionMessageHash(
                account,
                "propose",
                nonce
            );

        _verifyWebAuthnThreshold(
            account,
            accountConfigs[account].reconfigPolicy,
            accountConfigs[account].reconfigThreshold,
            challenge,
            proofs
        );

        actionNonce[account] = nonce + 1;

        uint64 timeSinceActivity =
            uint64(block.timestamp) -
            lastActivityAt[account];

        bool thresholdWeakened =
            config.reconfigThreshold <
            accountConfigs[account].reconfigThreshold;

        bool authenticatorsRemoved =
            config.authenticators.length <
            accountConfigs[account].authenticators.length;

        RiskScoring.AttemptContext memory ctx =
            RiskScoring.AttemptContext({
                timestamp: uint64(block.timestamp),
                timeSinceLastActivity: timeSinceActivity,
                isKnownDevicePattern: config.isKnownDevicePattern,
                recentFailedAttempts: recentFailedAttempts[account],
                thresholdWeakened: thresholdWeakened,
                authenticatorsRemoved: authenticatorsRemoved
            });

        uint8 riskScore =
            RiskScoring.computeRiskScore(ctx);

        bool requiresExtraConfirmation =
            RiskScoring.isHighRisk(riskScore);

        PendingReconfig storage pending =
            pendingConfigs[account];

        delete pending.authenticators;
        delete pending.signingPolicy;
        delete pending.reconfigPolicy;

        for (
            uint256 i = 0;
            i < config.authenticators.length;
            i++
        ) {
            pending.authenticators.push(
                config.authenticators[i]
            );
        }

        for (
            uint256 i = 0;
            i < config.signingPolicy.length;
            i++
        ) {
            pending.signingPolicy.push(
                config.signingPolicy[i]
            );
        }

        for (
            uint256 i = 0;
            i < config.reconfigPolicy.length;
            i++
        ) {
            pending.reconfigPolicy.push(
                config.reconfigPolicy[i]
            );
        }

        pending.signingThreshold =
            config.signingThreshold;

        pending.reconfigThreshold =
            config.reconfigThreshold;

        pending.proposedAt =
            uint64(block.timestamp);

        pending.exists = true;
        pending.riskScore = riskScore;
        pending.requiresExtraConfirmation =
            requiresExtraConfirmation;
        pending.extraConfirmationGiven = false;

        emit ReconfigurationProposed(
            account,
            accountConfigs[account].configVersion,
            pending.proposedAt,
            riskScore
        );
    }

    function confirmHighRiskProposal(
        address account,
        AuthProof calldata proof
    ) external {
        require(
            pendingConfigs[account].exists,
            "No pending reconfiguration"
        );

        uint64 nonce = actionNonce[account];

        bytes32 msgHash = _actionMessageHash(
            account,
            "confirm",
            nonce
        );

        Authenticator storage authr =
            _findAuthenticator(
                accountConfigs[account].authenticators,
                proof.authenticatorId
            );

        IdentityRegistry.Identity memory idy =
            IDENTITY_REGISTRY.getIdentity(
                authr.identityId
            );

        require(
            idy.active,
            "Authenticator identity inactive"
        );

        require(
            idy.owner == account,
            "Authenticator identity owner mismatch"
        );

        require(
            P256Verifier.verify(
                msgHash,
                proof.sigR,
                proof.sigS,
                idy.pubKeyX,
                idy.pubKeyY
            ),
            "Invalid confirmation signature"
        );

        actionNonce[account] = nonce + 1;

        pendingConfigs[account].extraConfirmationGiven = true;

        emit ExtraConfirmationGiven(account);
    }

    function confirmHighRiskProposalWithPasskey(
        address account,
        WebAuthnAuthProof[] calldata proofs
    ) external {
        require(
            pendingConfigs[account].exists,
            "No pending reconfiguration"
        );

        require(
            pendingConfigs[account].requiresExtraConfirmation,
            "Extra confirmation not required"
        );

        require(
            !pendingConfigs[account].extraConfirmationGiven,
            "Extra confirmation already given"
        );

        uint64 nonce = actionNonce[account];

        bytes32 challenge = _actionMessageHash(
            account,
            "confirm",
            nonce
        );

        _verifyWebAuthnThreshold(
            account,
            accountConfigs[account].reconfigPolicy,
            accountConfigs[account].reconfigThreshold,
            challenge,
            proofs
        );

        actionNonce[account] = nonce + 1;

        pendingConfigs[account].extraConfirmationGiven = true;

        emit ExtraConfirmationGiven(account);
    }

    function contestReconfigurationWithPasskey(
        address account,
        WebAuthnAuthProof[] calldata proofs
    ) external {
        require(
            pendingConfigs[account].exists,
            "No pending reconfiguration"
        );

        uint64 nonce = actionNonce[account];

        bytes32 challenge = _actionMessageHash(
            account,
            "contest",
            nonce
        );

        _verifyWebAuthnThreshold(
            account,
            accountConfigs[account].reconfigPolicy,
            accountConfigs[account].reconfigThreshold,
            challenge,
            proofs
        );

        actionNonce[account] = nonce + 1;

        recentFailedAttempts[account] += 1;

        delete pendingConfigs[account];

        emit ReconfigurationContested(
            account,
            uint64(block.timestamp)
        );
    }

    function contestReconfiguration(
        address account,
        AuthProof calldata proof
    ) external {
        require(
            pendingConfigs[account].exists,
            "No pending reconfiguration"
        );

        uint64 nonce = actionNonce[account];

        bytes32 msgHash = _actionMessageHash(
            account,
            "contest",
            nonce
        );

        Authenticator storage authr =
            _findAuthenticator(
                accountConfigs[account].authenticators,
                proof.authenticatorId
            );

        IdentityRegistry.Identity memory idy =
            IDENTITY_REGISTRY.getIdentity(
                authr.identityId
            );

        require(
            idy.active,
            "Authenticator identity inactive"
        );

        require(
            idy.owner == account,
            "Authenticator identity owner mismatch"
        );

        require(
            P256Verifier.verify(
                msgHash,
                proof.sigR,
                proof.sigS,
                idy.pubKeyX,
                idy.pubKeyY
            ),
            "Invalid contest signature"
        );

        actionNonce[account] = nonce + 1;

        recentFailedAttempts[account] += 1;

        delete pendingConfigs[account];

        emit ReconfigurationContested(
            account,
            uint64(block.timestamp)
        );
    }

    function activateReconfiguration(
        address account
    ) external {
        PendingReconfig storage pending =
            pendingConfigs[account];

        require(
            pending.exists,
            "No pending reconfiguration"
        );

        require(
            block.timestamp >=
                pending.proposedAt + RECONFIG_DELAY,
            "Delay not yet elapsed"
        );

        require(
            !pending.requiresExtraConfirmation ||
                pending.extraConfirmationGiven,
            "High-risk proposal requires extra confirmation"
        );

        Authenticator[] memory newAuthenticators =
            pending.authenticators;

        uint8[] memory newSigningPolicy =
            pending.signingPolicy;

        uint8 newSigningThreshold =
            pending.signingThreshold;

        uint8[] memory newReconfigPolicy =
            pending.reconfigPolicy;

        uint8 newReconfigThreshold =
            pending.reconfigThreshold;

        uint64 nextVersion =
            accountConfigs[account].configVersion + 1;

        delete accountConfigs[account];
        delete pendingConfigs[account];

        AuthConfig storage cfg =
            accountConfigs[account];

        for (uint256 i = 0; i < newAuthenticators.length; i++) {
            cfg.authenticators.push(
                newAuthenticators[i]
            );
        }

        for (uint256 i = 0; i < newSigningPolicy.length; i++) {
            cfg.signingPolicy.push(
                newSigningPolicy[i]
            );
        }

        for (uint256 i = 0; i < newReconfigPolicy.length; i++) {
            cfg.reconfigPolicy.push(
                newReconfigPolicy[i]
            );
        }

        cfg.signingThreshold =
            newSigningThreshold;

        cfg.reconfigThreshold =
            newReconfigThreshold;

        cfg.configVersion =
            nextVersion;

        lastActivityAt[account] =
            uint64(block.timestamp);

        emit ReconfigurationActivated(
            account,
            nextVersion
        );
    }

    // ---------- Verified transfers ----------

    function deposit(address account) external payable {
        accountBalance[account] += msg.value;

        knownDestination[account][msg.sender] = true;

        emit FundsReceived(
            account,
            msg.value
        );
    }

    function verifiedTransfer(
        address account,
        address to,
        uint256 amount,
        AuthProof[] calldata proofs
    ) external {
        require(
            to != address(0),
            "Cannot send to zero address"
        );

        require(
            accountBalance[account] >= amount,
            "Insufficient balance"
        );

        require(
            accountConfigs[account].configVersion > 0,
            "Not initialized"
        );

        uint64 nonce =
            actionNonce[account];

        bytes32 msgHash =
            _actionMessageHash(
                account,
                "transfer",
                nonce
            );

        _verifyThreshold(
            account,
            accountConfigs[account].signingPolicy,
            accountConfigs[account].signingThreshold,
            msgHash,
            proofs
        );

        actionNonce[account] = nonce + 1;

        if (knownDestination[account][to]) {
            accountBalance[account] -= amount;

            (bool sent, ) =
                to.call{value: amount}("");

            require(
                sent,
                "Transfer failed"
            );

            emit VerifiedTransferExecuted(
                account,
                to,
                amount,
                nonce
            );
        } else {
            require(
                !pendingTransfers[account].exists,
                "A transfer is already pending"
            );

            pendingTransfers[account] =
                PendingTransfer({
                    to: to,
                    amount: amount,
                    proposedAt: uint64(block.timestamp),
                    exists: true
                });

            emit TransferProposed(
                account,
                to,
                amount,
                uint64(block.timestamp)
            );
        }
    }

    function verifiedTransferWithPasskey(
        address account,
        address to,
        uint256 amount,
        WebAuthnAuthProof[] calldata proofs
    ) external {
        require(
            to != address(0),
            "Cannot send to zero address"
        );

        require(
            accountBalance[account] >= amount,
            "Insufficient balance"
        );

        require(
            accountConfigs[account].configVersion > 0,
            "Not initialized"
        );

        uint64 nonce = actionNonce[account];

        bytes32 challenge = _actionMessageHash(
            account,
            "transfer",
            nonce
        );

        _verifyWebAuthnThreshold(
            account,
            accountConfigs[account].signingPolicy,
            accountConfigs[account].signingThreshold,
            challenge,
            proofs
        );

        actionNonce[account] = nonce + 1;

        if (knownDestination[account][to]) {
            accountBalance[account] -= amount;

            (bool sent, ) = to.call{value: amount}("");

            require(
                sent,
                "Transfer failed"
            );

            emit VerifiedTransferExecuted(
                account,
                to,
                amount,
                nonce
            );
        } else {
            require(
                !pendingTransfers[account].exists,
                "A transfer is already pending"
            );

            pendingTransfers[account] = PendingTransfer({
                to: to,
                amount: amount,
                proposedAt: uint64(block.timestamp),
                exists: true
            });

            emit TransferProposed(
                account,
                to,
                amount,
                uint64(block.timestamp)
            );
        }
    }

    function contestTransferWithPasskey(
        address account,
        WebAuthnAuthProof[] calldata proofs
    ) external {
        require(
            pendingTransfers[account].exists,
            "No pending transfer"
        );

        uint64 nonce = actionNonce[account];

        bytes32 challenge = _actionMessageHash(
            account,
            "transfercontest",
            nonce
        );

        _verifyWebAuthnThreshold(
            account,
            accountConfigs[account].signingPolicy,
            accountConfigs[account].signingThreshold,
            challenge,
            proofs
        );

        actionNonce[account] = nonce + 1;

        address to = pendingTransfers[account].to;

        delete pendingTransfers[account];

        emit TransferContested(
            account,
            to,
            uint64(block.timestamp)
        );
    }

    function contestTransfer(
        address account,
        AuthProof calldata proof
    ) external {
        require(
            pendingTransfers[account].exists,
            "No pending transfer"
        );

        uint64 nonce =
            actionNonce[account];

        bytes32 msgHash =
            _actionMessageHash(
                account,
                "transfercontest",
                nonce
            );

        Authenticator storage authr =
            _findAuthenticator(
                accountConfigs[account].authenticators,
                proof.authenticatorId
            );

        IdentityRegistry.Identity memory idy =
            IDENTITY_REGISTRY.getIdentity(
                authr.identityId
            );

        require(
            idy.active,
            "Authenticator identity inactive"
        );

        require(
            idy.owner == account,
            "Authenticator identity owner mismatch"
        );

        require(
            P256Verifier.verify(
                msgHash,
                proof.sigR,
                proof.sigS,
                idy.pubKeyX,
                idy.pubKeyY
            ),
            "Invalid contest signature"
        );

        actionNonce[account] = nonce + 1;

        address to =
            pendingTransfers[account].to;

        delete pendingTransfers[account];

        emit TransferContested(
            account,
            to,
            uint64(block.timestamp)
        );
    }

    function activateTransfer(
        address account
    ) external {
        PendingTransfer memory pending =
            pendingTransfers[account];

        require(
            pending.exists,
            "No pending transfer"
        );

        require(
            block.timestamp >=
                pending.proposedAt + TRANSFER_DELAY,
            "Delay not yet elapsed"
        );

        require(
            accountBalance[account] >=
                pending.amount,
            "Insufficient balance"
        );

        delete pendingTransfers[account];

        accountBalance[account] -=
            pending.amount;

        knownDestination[account][pending.to] = true;

        (bool sent, ) =
            pending.to.call{
                value: pending.amount
            }("");

        require(
            sent,
            "Transfer failed"
        );

        emit NewDestinationTransferActivated(
            account,
            pending.to,
            pending.amount
        );
    }
}
