<?php

namespace OAuth2\Storage;

class RefreshTokenExpiryTest extends BaseTest
{
    /**
     * An expiry of 0 is the "never expires" sentinel set by
     * ResponseType\AccessToken::createAccessToken when refresh_token_lifetime
     * is 0. It must not be stored as the Unix epoch: west of UTC that formats
     * to a 1969 datestring, which is below the MySQL TIMESTAMP floor and is
     * rejected under STRICT_TRANS_TABLES.
     *
     * @dataProvider provideStorage
     */
    public function testSetRefreshTokenWithNeverExpiresSentinel(RefreshTokenInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        $success = $storage->setRefreshToken('never-expires-refreshtoken', 'client ID', 'SOMEUSERID', 0);
        $this->assertTrue($success);

        $token = $storage->getRefreshToken('never-expires-refreshtoken');
        $this->assertNotNull($token);
        $this->assertArrayHasKey('expires', $token);

        // The contract every backend shares: the token must survive the check
        // GrantType\RefreshToken makes before accepting it. Backends that keep
        // the raw integer report 0 here; those that store a datestring report a
        // far-future timestamp. Both must read as "not expired".
        $isExpired = $token['expires'] > 0 && $token['expires'] < time();
        $this->assertFalse($isExpired, 'a never-expiring refresh token was treated as expired');

        // Datestring-backed storage must not round-trip to the epoch: west of
        // UTC that is a 1969 datestring, which MySQL rejects under
        // STRICT_TRANS_TABLES and which reads back as "expired in 1970".
        if ($storage instanceof Pdo) {
            $this->assertGreaterThan(time(), $token['expires']);
        }
    }

    /**
     * A real expiry must still round-trip exactly - the sentinel handling
     * above must not disturb ordinary tokens.
     *
     * @dataProvider provideStorage
     */
    public function testSetRefreshTokenWithRealExpiryIsUnchanged(RefreshTokenInterface $storage)
    {
        if ($storage instanceof NullStorage) {
            $this->markTestSkipped('Skipped Storage: ' . $storage->getMessage());

            return;
        }

        $expires = time() + 20;
        $success = $storage->setRefreshToken('real-expiry-refreshtoken', 'client ID', 'SOMEUSERID', $expires);
        $this->assertTrue($success);

        $token = $storage->getRefreshToken('real-expiry-refreshtoken');
        $this->assertNotNull($token);
        $this->assertEquals($expires, $token['expires']);
    }
}
