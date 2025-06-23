<?php
namespace VirtaSys\AI;

use VirtaSys\Compliance\ComplianceChecker;
use VirtaSys\Blockchain\BlockchainLogger;

class ChatEngine {
    private ComplianceChecker $complianceChecker;
    private BlockchainLogger $blockchainLogger;

    public function __construct() {
        $this->complianceChecker = new ComplianceChecker();
        $this->blockchainLogger = new BlockchainLogger();
    }

    public function processChat(array $request): array {
        $this->complianceChecker->validateTransaction($request);
        $response = ARTEMISAI::generateResponse($request['query']);
        $auditId = $this->blockchainLogger->logTransaction($request['user_id'], hash('sha256', $response));
        return [
            'response' => $response,
            'compliance_audit_id' => $auditId,
            'blockchain_verified' => true
        ];
    }
}
