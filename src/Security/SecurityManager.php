<?php
namespace VirtaSys\Security;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Exception;

class SecurityManager {
    private const JWT_SECRET = 'your-secure-secret-key';
    private const AES_KEY = '32-char-random-key-here-1234567890ab';
    private const AES_IV = '16-char-random-iv!';

    public static function validateJWT(string $token): bool {
        try {
            $decoded = JWT::decode($token, new Key(self::JWT_SECRET, 'HS256'));
            return true;
        } catch (Exception $e) {
            return false;
        }
    }

    public static function encryptData(string $data): string {
        return openssl_encrypt($data, 'AES-256-CBC', self::AES_KEY, 0, self::AES_IV);
    }

    public static function decryptData(string $encrypted): string {
        return openssl_decrypt($encrypted, 'AES-256-CBC', self::AES_KEY, 0, self::AES_IV);
    }
}
