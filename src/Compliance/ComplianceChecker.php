<?php
namespace VirtaSys\Compliance;

use VirtaSys\Security\SecurityManager;
use VirtaSys\AI\ARTEMISML;
use Exception;

class ComplianceChecker {
    private const COMPLIANCE_STANDARDS = ['GDPR', 'SOC2', 'ISO27001', '18 U.S.C. § 1030'];

    public function validateTransaction(array $transaction): bool {
        if (!in_array($transaction['compliance_level'] ?? '', self::COMPLIANCE_STANDARDS)) {
            throw new Exception("Compliance violation: Invalid level");
        }
        if (!SecurityManager::validateJWT($transaction['session_token'] ?? '')) {
            throw new Exception("Compliance violation: Invalid session");
        }
        ARTEMISML::analyzeBehavior($transaction['user_id'], 'compliance_check', $transaction);
        return true;
    }
}
