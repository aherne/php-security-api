<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Encapsulates a SynchronizerToken, to be used for CSRF prevention or for stateless replacement of sessions.
 */
class SynchronizerToken
{
    private string $ip;
    private string $salt;

    /**
     * Constructs a synchronizer token.
     *
     * @param string $ip   Ip address for whom token will be registered.
     * @param string $salt Strong encryption/decryption password.
     */
    public function __construct(string $ip, string $salt)
    {
        $this->ip = $ip;
        $this->salt = $salt;
    }

    /**
     * Creates a token.
     *
     * @param  int|string|null $userID         Unique user identifier for whom token will be registered
     * @param  int             $expirationTime Time by which token expires.
     * @throws EncryptionException If encryption of token fails.
     * @return string Encrypted token.
     */
    public function encode(int|string|null $userID, int $expirationTime=3600): string
    {
        $currentTime = time();
        $payload = ["uid"=>$userID, "ip"=>$this->ip, "time"=>$currentTime, "expiration"=>($currentTime+$expirationTime)];
        $encryption = new Encryption($this->salt);
        return $encryption->encrypt(json_encode($payload));
    }

    /**
     * Decodes a token and returns user id.
     *
     * @param  string $token           Encrypted token.
     * @param  int    $maximumLifetime Time by which token should be regenerated.
     * @throws Exception If token fails validations.
     * @throws RegenerationException If token needs to be refreshed
     * @throws ExpiredException If token expired beyond regeneration threshold.
     * @throws EncryptionException If decryption of token fails.
     * @return int|string|null Unique user identifier.
     */
    public function decode(string $token, int $maximumLifetime=0): int|string|null
    {
        $encryption = new Encryption($this->salt);
        $decryptedValue = $encryption->decrypt($token);
        $parts = json_decode($decryptedValue, true);

        // validate token
        if ($this->ip!=$parts["ip"]) {
            throw new Exception("Token was issued from a different ip!");
        }
        $currentTime = time();
        if ($currentTime > $parts["expiration"]) {
            throw new ExpiredException("Token has expired!");
        }
        if ($maximumLifetime && ($currentTime-$parts["time"])>$maximumLifetime) {
            $tre = new RegenerationException("Token needs to be regenerated!");
            $tre->setPayload($parts["uid"]);
            throw $tre;
        }

        // return user identifier
        return (!empty($parts["uid"]) ? $parts["uid"] : null);
    }
}
