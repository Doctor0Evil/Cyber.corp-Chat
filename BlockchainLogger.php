<?php
namespace VirtaSys\Blockchain;

use VirtaSys\Utils\VirtualDiskStorage;
use VirtaSys\Security\AES256;
use DateTime;

class BlockchainLogger {
    private string $network;

    public function __construct(string $network = 'polygon') {
        $this->network = $network;
    }

    public function logTransaction(string $userId, string $chatHash): string {
        $txHash = hash('sha256', $userId . $chatHash . microtime());
        $payload = json_encode([
            'user_id' => $userId,
            'chat_hash' => $chatHash,
            'timestamp' => (new DateTime())->format('c'),
            'network' => $this->network
        ]);
        VirtualDiskStorage::write("z://cybercorp/audit/$txHash.json", AES256::encrypt($payload));
        // Log to external ledger here (e.g., Polygon)
        return $txHash;
    }
}
