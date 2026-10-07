

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/AuthConfigManager.sol";
import "../src/IdentityRegistry.sol";

contract ReentrantAttacker {
    AuthConfigManager public target;
    address public victimAccount;
    uint256 public reentryAttempts;

    constructor(address _target, address _victimAccount) {
        target = AuthConfigManager(_target);
        victimAccount = _victimAccount;
    }

    receive() external payable {
        reentryAttempts++;
        if (reentryAttempts == 1) {
            try target.activateTransfer(victimAccount) {} catch {}
        }
    }
}

contract AuthConfigManagerTransferTest is Test {
    AuthConfigManager manager;
    IdentityRegistry registry;

    bytes32 constant OWNER_PUB_X =
        0x359ab5a0fa01191819bcac9e60ceed35ecdd3941be44fc08168b14800ee74017;

    bytes32 constant OWNER_PUB_Y =
        0x91f00999661d51c3731b430e881896165d31d434edc88f5186aac853b41f89ff;

    bytes32 identityId;
    address recipient;

    function setUp() public {
        registry = new IdentityRegistry();
        manager = new AuthConfigManager(address(registry));

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

        manager.deposit{value: 10 ether}(address(this));
        recipient = makeAddr("anchor-test-recipient");
    }

    function _transferProofN0()
        internal
        pure
        returns (AuthConfigManager.AuthProof[] memory)
    {
        AuthConfigManager.AuthProof[] memory proofs =
            new AuthConfigManager.AuthProof[](1);

        proofs[0] = AuthConfigManager.AuthProof({
            authenticatorId: 1,
            sigR:
                0x48c406f46099dc0caa9fa7c09d980c0e9d5be0941f8681e49b3fdc79af667887,
            sigS:
                0x70bb9ed9549a767c539e253dc7e54f9d4001ae8d9e08d8f3e25ea0ac3db6b1db
        });

        return proofs;
    }

    function _transferProofN1()
        internal
        pure
        returns (AuthConfigManager.AuthProof[] memory)
    {
        AuthConfigManager.AuthProof[] memory proofs =
            new AuthConfigManager.AuthProof[](1);

        proofs[0] = AuthConfigManager.AuthProof({
            authenticatorId: 1,
            sigR:
                0x4c245fefa017da0ecd09dc4e46add1b1447a35f8dafc94da730f9a854ec6219e,
            sigS:
                0xff21dbbb550477681f18dd2f07ee8e16bb197c08f78d171a2d7a014baaea95e6
        });

        return proofs;
    }

    function testDepositMarksSelfAsKnownDestination() public view {
        assertTrue(manager.knownDestination(address(this), address(this)));
    }

    function testTransferToNewDestinationIsQueuedNotExecuted() public {
        uint256 recipientBalanceBefore = recipient.balance;

        manager.verifiedTransfer(
            address(this),
            recipient,
            1 ether,
            _transferProofN0()
        );

        assertEq(recipient.balance, recipientBalanceBefore);
        assertEq(manager.accountBalance(address(this)), 10 ether);

        (
            address to,
            uint256 amount,
            ,
            bool exists
        ) = manager.pendingTransfers(address(this));

        assertTrue(exists);
        assertEq(to, recipient);
        assertEq(amount, 1 ether);
    }

    function testCannotActivateTransferBeforeDelay() public {
        manager.verifiedTransfer(
            address(this),
            recipient,
            1 ether,
            _transferProofN0()
        );

        vm.expectRevert("Delay not yet elapsed");
        manager.activateTransfer(address(this));
    }

    function testActivateTransferAfterDelaySendsFundsAndMarksKnown()
        public
    {
        uint256 recipientBalanceBefore = recipient.balance;

        manager.verifiedTransfer(
            address(this),
            recipient,
            1 ether,
            _transferProofN0()
        );

        vm.warp(block.timestamp + 1 hours + 1);
        manager.activateTransfer(address(this));

        assertEq(
            recipient.balance,
            recipientBalanceBefore + 1 ether
        );

        assertEq(
            manager.accountBalance(address(this)),
            9 ether
        );

        assertTrue(
            manager.knownDestination(address(this), recipient)
        );

        (, , , bool exists) =
            manager.pendingTransfers(address(this));

        assertFalse(exists);
    }

    function testKnownDestinationTransferExecutesInstantly() public {
        uint256 recipientBalanceBefore = recipient.balance;

        manager.verifiedTransfer(
            address(this),
            recipient,
            1 ether,
            _transferProofN0()
        );

        vm.warp(block.timestamp + 1 hours + 1);
        manager.activateTransfer(address(this));

        assertTrue(
            manager.knownDestination(address(this), recipient)
        );

        manager.verifiedTransfer(
            address(this),
            recipient,
            2 ether,
            _transferProofN1()
        );

        assertEq(
            recipient.balance,
            recipientBalanceBefore + 3 ether
        );

        assertEq(
            manager.accountBalance(address(this)),
            7 ether
        );

        (, , , bool exists) =
            manager.pendingTransfers(address(this));

        assertFalse(exists);
    }

    function testContestKillsQueuedTransfer() public {
        uint256 recipientBalanceBefore = recipient.balance;

        manager.verifiedTransfer(
            address(this),
            recipient,
            1 ether,
            _transferProofN0()
        );

        AuthConfigManager.AuthProof memory contestProof =
            AuthConfigManager.AuthProof({
                authenticatorId: 1,
                sigR:
                    0xb3a153c3283bd35d0c1824503ec0e261c45decf1782b2c62fa5931bf88f9a337,
                sigS:
                    0x6f26299027e8469a04feb0737b9213a960e3ddc3d5d7ebb524d180aa55256bb3
            });

        manager.contestTransfer(
            address(this),
            contestProof
        );

        (, , , bool exists) =
            manager.pendingTransfers(address(this));

        assertFalse(exists);

        vm.warp(block.timestamp + 1 hours + 1);

        vm.expectRevert("No pending transfer");
        manager.activateTransfer(address(this));

        assertEq(
            recipient.balance,
            recipientBalanceBefore
        );

        assertEq(
            manager.accountBalance(address(this)),
            10 ether
        );

        assertFalse(
            manager.knownDestination(address(this), recipient)
        );
    }

    function testCannotQueueSecondTransferWhilePending() public {
        manager.verifiedTransfer(
            address(this),
            recipient,
            1 ether,
            _transferProofN0()
        );

        vm.expectRevert("A transfer is already pending");

        manager.verifiedTransfer(
            address(this),
            makeAddr("someone-else"),
            1 ether,
            _transferProofN1()
        );
    }

    function testCannotTransferToZeroAddress() public {
        vm.expectRevert("Cannot send to zero address");

        manager.verifiedTransfer(
            address(this),
            address(0),
            1 ether,
            _transferProofN0()
        );
    }

    function testCannotTransferMoreThanBalance() public {
        vm.expectRevert("Insufficient balance");

        manager.verifiedTransfer(
            address(this),
            recipient,
            100 ether,
            _transferProofN0()
        );
    }

    function testCannotSpendAnotherAccountsBalance() public {
        address stranger = makeAddr("stranger-account");

        vm.deal(stranger, 5 ether);

        vm.prank(stranger);
        manager.deposit{value: 5 ether}(stranger);

        assertEq(
            manager.accountBalance(stranger),
            5 ether
        );

        assertEq(
            manager.accountBalance(address(this)),
            10 ether
        );

        vm.expectRevert();

        manager.verifiedTransfer(
            stranger,
            address(this),
            1 ether,
            _transferProofN0()
        );

        assertEq(
            manager.accountBalance(stranger),
            5 ether
        );

        assertEq(
            manager.accountBalance(address(this)),
            10 ether
        );
    }

    function testActivateTransferIsNotReentrant() public {
        ReentrantAttacker attacker =
            new ReentrantAttacker(
                address(manager),
                address(this)
            );

        manager.verifiedTransfer(
            address(this),
            address(attacker),
            1 ether,
            _transferProofN0()
        );

        vm.warp(block.timestamp + 1 hours + 1);

        uint256 balanceBefore =
            manager.accountBalance(address(this));

        manager.activateTransfer(address(this));

        assertEq(
            balanceBefore -
                manager.accountBalance(address(this)),
            1 ether
        );

        assertEq(
            address(attacker).balance,
            1 ether
        );

        assertEq(
            attacker.reentryAttempts(),
            1
        );
    }
}
