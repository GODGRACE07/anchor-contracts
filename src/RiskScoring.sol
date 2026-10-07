// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

library RiskScoring {
    struct AttemptContext {
        uint64 timestamp;
        uint64 timeSinceLastActivity;
        bool isKnownDevicePattern;
        uint32 recentFailedAttempts;
        bool thresholdWeakened;
        bool authenticatorsRemoved;
    }

    function computeRiskScore(
        AttemptContext memory ctx
    ) internal pure returns (uint8) {
        uint256 score = 0;

        if (
            ctx.timeSinceLastActivity > 0 &&
            ctx.timeSinceLastActivity < 1 hours
        ) {
            score += 20;
        }

        if (!ctx.isKnownDevicePattern) {
            score += 40;
        }

        if (ctx.recentFailedAttempts > 0) {
            score += 30;

            if (ctx.recentFailedAttempts > 3) {
                score += 10;
            }
        }

        if (ctx.thresholdWeakened) {
            score += 35;
        }

        if (ctx.authenticatorsRemoved) {
            score += 35;
        }

        if (score > 100) {
            score = 100;
        }

        return uint8(score);
    }

    function isHighRisk(
        uint8 score
    ) internal pure returns (bool) {
        return score >= 60;
    }
}
