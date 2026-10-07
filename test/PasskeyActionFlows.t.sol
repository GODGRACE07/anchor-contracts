// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/AuthConfigManager.sol";
import "../src/IdentityRegistry.sol";
import "../src/WebAuthnVerifier.sol";

contract PasskeyActionFlowsTest is Test {
    AuthConfigManager manager;
    IdentityRegistry registry;

    bytes32 constant OWNER_PUB_X =
        0x359ab5a0fa01191819bcac9e60ceed35ecdd3941be44fc08168b14800ee74017;

    bytes32 constant OWNER_PUB_Y =
        0x91f00999661d51c3731b430e881896165d31d434edc88f5186aac853b41f89ff;

    address account;
    address recipient;

    bytes32 identityId;

    function setUp() public {
        registry = new IdentityRegistry();
        manager = new AuthConfigManager(address(registry));

        account = address(this);
        recipient = makeAddr("passkey-recipient");

        identityId = registry.register(
            OWNER_PUB_X,
            OWNER_PUB_Y,
            0x6dff0fe8309f2454e192031173bc6bce2b4bb050ee93fd096833ffd132cba8fa,
            0x5363fcfd857e1b31dd6e1de820b8dd9c0cfa753260831933448db8438a04bdf0,
            "Owner"
        );

        AuthConfigManager.Authenticator[] memory auths =
            new AuthConfigManager.Authenticator[](1);

        auths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityId
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        manager.initializeConfig(
            auths,
            policy,
            1,
            policy,
            1
        );
    }

    function _proof(
        bytes32 sigR,
        bytes32 sigS,
        bytes32 challenge
    )
        internal
        pure
        returns (AuthConfigManager.WebAuthnAuthProof[] memory)
    {
        AuthConfigManager.WebAuthnAuthProof[] memory proofs =
            new AuthConfigManager.WebAuthnAuthProof[](1);

        proofs[0] = AuthConfigManager.WebAuthnAuthProof({
            authenticatorId: 1,
            proof: WebAuthnVerifier.WebAuthnProof({
                authenticatorData:
                    hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000002",
                clientDataJSONPrefix:
                    '{"type":"webauthn.get","challenge":"',
                clientDataJSONSuffix:
                    '","origin":"http://localhost:3000","crossOrigin":false}',
                sigR: sigR,
                sigS: sigS
            })
        });

        // Silence unused-parameter warning while making the expected
        // challenge explicit at the call site.
        challenge;

        return proofs;
    }

    function _proposalProof()
        internal
        pure
        returns (AuthConfigManager.WebAuthnAuthProof[] memory)
    {
        return _proof(
            0xdc54137f7e055692b44d7ff945ebfaf97fb36887e0e98094e4a2ed6bb1588c47,
            0xf4d09d83f9ccd97924bcbd1d9ae0ca0a83cbe3aa9e1e49067db21d8b1c857f36,
            0x40d5352a3e5baf47b68e51af9ae06054240b1a26e415da7523340c05ece18d0d
        );
    }

    function _confirmProof()
        internal
        pure
        returns (AuthConfigManager.WebAuthnAuthProof[] memory)
    {
        return _proof(
            0x5eb7b879509acd87015658e87b501698adf6677139c2d1df235d8346329eea26,
            0x0e486f0ac23436124f61d4be49c2470ca6a288b0f81dc8fdb3274595f14d25f4,
            0xa5bc932a9689d1d151aa55b2489a765ccac4d897cbbe17dabc8157cc05e1a7d5
        );
    }

    function _contestProof()
        internal
        pure
        returns (AuthConfigManager.WebAuthnAuthProof[] memory)
    {
        return _proof(
            0xfe42899d90932e4631ab95fd95eb13d19623a4dd90d6433208bab3051f8d7e1f,
            0x7d2860a40859934e9eec22e86f4056b02b7b9dc53f0335ebb4a52461d65b1b83,
            0xa15ef323cb346885af1369fdc922236cb7b51584bd667ca97bbf386c7b307cb3
        );
    }

    function _transferProof()
        internal
        pure
        returns (AuthConfigManager.WebAuthnAuthProof[] memory)
    {
        return _proof(
            0x87aa9834e5b4939585ca6756adffb5ed6ea213b0025ee11fd057853d631c7d49,
            0x4538a5f3cfeaf36415bbd774b90952f70109e0a185ab7b588b2d7b2b6c57cded,
            0x5ba635c3d870633f694f30164b8094f5a57f98c4f51913e11d9e32f75d4e6730
        );
    }

    function _transferContestProof()
        internal
        pure
        returns (AuthConfigManager.WebAuthnAuthProof[] memory)
    {
        return _proof(
            0x386410ce7e433ac83df600be1ac219be3f77b1206c7a938adc3e63a5429306a3,
            0xcdea9f9f576188f48971898b82403f335136db8ae023c9897268f80af3b33688,
            0xbd143456d0fc07bc082b0b130b53515a20004a55412e5b91be57684821fa1976
        );
    }

    function _highRiskProposal() internal {
        AuthConfigManager.Authenticator[] memory newAuths =
            new AuthConfigManager.Authenticator[](1);

        newAuths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityId
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        manager.proposeReconfigurationWithPasskey(
            abi.encode(
                account,
                newAuths,
                policy,
                uint8(1),
                policy,
                uint8(1),
                false,
                _proposalProof()
            )
        );
    }

    function testConfirmHighRiskProposalWithPasskey() public {
        _highRiskProposal();

        // The test configuration itself is not high risk, so the
        // production function should reject unnecessary confirmation.
        vm.expectRevert("Extra confirmation not required");

        manager.confirmHighRiskProposalWithPasskey(
            account,
            _confirmProof()
        );
    }

    function testContestReconfigurationWithPasskey() public {
        _highRiskProposal();

        manager.contestReconfigurationWithPasskey(
            account,
            _contestProof()
        );

        AuthConfigManager.PendingReconfig memory pending =
            manager.getPendingReconfig(account);

        assertFalse(pending.exists);
    }

    function testVerifiedTransferWithPasskey() public {
        manager.deposit{value: 2 ether}(account);

        uint256 beforeBalance = recipient.balance;

        manager.verifiedTransferWithPasskey(
            account,
            recipient,
            1 ether,
            _transferProof()
        );

        assertEq(recipient.balance, beforeBalance);
        assertEq(manager.accountBalance(account), 2 ether);

        (
            address to,
            uint256 amount,
            ,
            bool exists
        ) = manager.pendingTransfers(account);

        assertTrue(exists);
        assertEq(to, recipient);
        assertEq(amount, 1 ether);
    }

    function testPasskeyIdentityCannotAuthorizeDifferentAccount() public {
        // Account B genuinely owns this identity.
        address accountB = address(0x000000000000000000000000000000000000b0b0);

        IdentityRegistry registryB = new IdentityRegistry();
        AuthConfigManager managerB = new AuthConfigManager(address(registryB));

        vm.prank(accountB);
        bytes32 identityB = registryB.register(
            OWNER_PUB_X,
            OWNER_PUB_Y,
            0x31e10dc6dfc5edbff9fdd5fea59a31f315cc5bd5b10d4b6c5f0a0e4016637afc,
            0xbd674a0b3c985efd2e6544b51ab63ac917b571732548fe6be62fb4feca24c087,
            "Account B"
        );

        AuthConfigManager.Authenticator[] memory auths =
            new AuthConfigManager.Authenticator[](1);

        auths[0] = AuthConfigManager.Authenticator({
            id: 1,
            scheme: AuthConfigManager.Scheme.P256_PASSKEY,
            identityId: identityB
        });

        uint8[] memory policy = new uint8[](1);
        policy[0] = 1;

        // Account A initializes a configuration that incorrectly references
        // Account B's passkey. The action must still be rejected because
        // the identity is not owned by Account A.
        managerB.initializeConfig(
            auths,
            policy,
            1,
            policy,
            1
        );

        managerB.deposit{value: 1 ether}(account);

        vm.expectRevert("Authenticator identity owner mismatch");

        managerB.verifiedTransferWithPasskey(
            account,
            recipient,
            1 ether,
            _transferProof()
        );

        assertEq(managerB.accountBalance(account), 1 ether);
    }

    function testContestTransferWithPasskey() public {
        manager.deposit{value: 2 ether}(account);

        manager.verifiedTransferWithPasskey(
            account,
            recipient,
            1 ether,
            _transferProof()
        );

        manager.contestTransferWithPasskey(
            account,
            _transferContestProof()
        );

        (
            ,
            ,
            ,
            bool exists
        ) = manager.pendingTransfers(account);

        assertFalse(exists);
        assertEq(manager.accountBalance(account), 2 ether);
    }
}
