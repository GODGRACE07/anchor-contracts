// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/RiskScoring.sol";

contract RiskScoringTest is Test {
    function testNormalActivityIsLowRisk() public pure {
        RiskScoring.AttemptContext memory ctx =
            RiskScoring.AttemptContext({
                timestamp: 1000,
                timeSinceLastActivity: 2 hours,
                isKnownDevicePattern: true,
                recentFailedAttempts: 0,
                thresholdWeakened: false,
                authenticatorsRemoved: false
            });

        uint8 score = RiskScoring.computeRiskScore(ctx);

        assertEq(score, 0);
        assertFalse(RiskScoring.isHighRisk(score));
    }

    function testNewDeviceAloneIsModerateRisk() public pure {
        RiskScoring.AttemptContext memory ctx =
            RiskScoring.AttemptContext({
                timestamp: 1000,
                timeSinceLastActivity: 2 hours,
                isKnownDevicePattern: false,
                recentFailedAttempts: 0,
                thresholdWeakened: false,
                authenticatorsRemoved: false
            });

        uint8 score = RiskScoring.computeRiskScore(ctx);

        assertEq(score, 40);
        assertFalse(RiskScoring.isHighRisk(score));
    }

    function testSuddenActivityAfterSilencePlusNewDeviceIsHighRisk()
        public
        pure
    {
        RiskScoring.AttemptContext memory ctx =
            RiskScoring.AttemptContext({
                timestamp: 1000,
                timeSinceLastActivity: 10 minutes,
                isKnownDevicePattern: false,
                recentFailedAttempts: 0,
                thresholdWeakened: false,
                authenticatorsRemoved: false
            });

        uint8 score = RiskScoring.computeRiskScore(ctx);

        assertEq(score, 60);
        assertTrue(RiskScoring.isHighRisk(score));
    }

    function testRepeatedFailuresEscalateScore() public pure {
        RiskScoring.AttemptContext memory ctx =
            RiskScoring.AttemptContext({
                timestamp: 1000,
                timeSinceLastActivity: 2 hours,
                isKnownDevicePattern: true,
                recentFailedAttempts: 5,
                thresholdWeakened: false,
                authenticatorsRemoved: false
            });

        uint8 score = RiskScoring.computeRiskScore(ctx);

        assertEq(score, 40);
    }

    function testWorstCaseHitsCapAt100() public pure {
        RiskScoring.AttemptContext memory ctx =
            RiskScoring.AttemptContext({
                timestamp: 1000,
                timeSinceLastActivity: 10 minutes,
                isKnownDevicePattern: false,
                recentFailedAttempts: 10,
                thresholdWeakened: true,
                authenticatorsRemoved: true
            });

        uint8 score = RiskScoring.computeRiskScore(ctx);

        assertEq(score, 100);
        assertTrue(RiskScoring.isHighRisk(score));
    }

    function testZeroTimeSinceActivityDoesNotFalselyFlag() public pure {
        RiskScoring.AttemptContext memory ctx =
            RiskScoring.AttemptContext({
                timestamp: 1000,
                timeSinceLastActivity: 0,
                isKnownDevicePattern: true,
                recentFailedAttempts: 0,
                thresholdWeakened: false,
                authenticatorsRemoved: false
            });

        uint8 score = RiskScoring.computeRiskScore(ctx);

        assertEq(score, 0);
    }

    function testThresholdWeakenedAloneIsHighRisk() public pure {
        RiskScoring.AttemptContext memory ctx =
            RiskScoring.AttemptContext({
                timestamp: 1000,
                timeSinceLastActivity: 2 hours,
                isKnownDevicePattern: true,
                recentFailedAttempts: 0,
                thresholdWeakened: true,
                authenticatorsRemoved: false
            });

        uint8 score = RiskScoring.computeRiskScore(ctx);

        assertEq(score, 35);
        assertFalse(RiskScoring.isHighRisk(score));
    }

    function testAuthenticatorsRemovedAloneIsHighRisk() public pure {
        RiskScoring.AttemptContext memory ctx =
            RiskScoring.AttemptContext({
                timestamp: 1000,
                timeSinceLastActivity: 2 hours,
                isKnownDevicePattern: true,
                recentFailedAttempts: 0,
                thresholdWeakened: false,
                authenticatorsRemoved: true
            });

        uint8 score = RiskScoring.computeRiskScore(ctx);

        assertEq(score, 35);
        assertFalse(RiskScoring.isHighRisk(score));
    }

    function testThresholdWeakenedPlusRemovedCrossesHighRiskThreshold()
        public
        pure
    {
        RiskScoring.AttemptContext memory ctx =
            RiskScoring.AttemptContext({
                timestamp: 1000,
                timeSinceLastActivity: 2 hours,
                isKnownDevicePattern: true,
                recentFailedAttempts: 0,
                thresholdWeakened: true,
                authenticatorsRemoved: true
            });

        uint8 score = RiskScoring.computeRiskScore(ctx);

        assertEq(score, 70);
        assertTrue(RiskScoring.isHighRisk(score));
    }
}
