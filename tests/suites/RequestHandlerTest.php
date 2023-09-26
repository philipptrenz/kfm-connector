<?php
use Kirby\Cms\App;
use Kirby\Cache\Cache;
use Kirby\Http\Request;
use PhilippTrenz\KFMConnector\JwksException;
use PHPUnit\Framework\TestCase;
use PhilippTrenz\KFMConnector\RequestHandler;
use PhilippTrenz\KFMConnector\JwtCertificate;

final class RequestHandlerTest extends TestCase {

    private App $kirby;
    private Cache $cache;
    private string $audience;
    private string $issuer;
    private int|null $cacheDuration;

    protected function setUp() : void
    {        
        $this->kirby = kirby();

        $this->cache         = $this->kirby->cache('philipptrenz.kfm-connector');
        $this->audience      = $this->kirby->site()->url();
        $this->issuer        = $this->kirby->option('philipptrenz.kfm-connector.issuer', null);
        $this->cacheDuration = $this->kirby->option('philipptrenz.kfm-connector.jwksCacheDuration', null);

        $this->cache->flush();
    }

    protected function tearDown() : void 
    {
        $this->cache->flush();
    }

    public function testIssuer() : void
    {
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);
        $this->assertEquals($h->getIssuer(), 'https://my-kfm-instance');
    }

    public function testExpectedAudience() : void
    {
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);
        $this->assertEquals($h->getAudience(), 'https://my-kirby-instance');
    }

    public function testJwksUrl() : void
    {
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);
        $this->assertEquals($h->getJwksUrl(), 'https://my-kfm-instance/api/jwks');
    }

    public function testJwksCacheDuration() : void
    {
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);
        $this->assertEquals($h->getJwksCacheDuration(), 60*24);
    }

    public function testJwksCacheDurationFallback() : void
    {
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, null);
        $this->assertEquals($h->getJwksCacheDuration(), 3*60*24);
    }

    public function testJwksCacheDurationFallback2() : void
    {
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer);
        $this->assertEquals($h->getJwksCacheDuration(), 3*60*24);
    }

    private function setupJWTAuthorization(string $issuer, $audience, $jwtValidInMinutes, $jwtValidForMinutes, int $certBits=4096): string
    {
        // Create RSA certificate for JWTs
        $cert = new JwtCertificate($certBits);
        
        // Populate cache with jwks
        $this->cache->set(RequestHandler::$JWKS_CACHE_KEY, JwtCertificate::toJWKS($cert), 1);

        // Create JWT
        $jwt = $cert->issueJWT($issuer, $audience, $jwtValidInMinutes, $jwtValidForMinutes);

        return $jwt;
    }

    public function testValidAuthenticationWithJwksFromCache() : void 
    {        
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);
        
        $jwt = $this->setupJWTAuthorization(
            $this->issuer,
            $this->audience,
            0,
            5,
            4096
        );

        // Create new app environment with authorization header
        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
			]
		]);

        // Build dummy request, which includes header
        $request = new Request();

        $this->assertTrue($h->isAuthorized($request, $this->kirby->visitor()));
    }

    public function testExpiredAuthenticationWithJwksFromCache() : void 
    {        
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);
    
        $jwt = $this->setupJWTAuthorization(
            $this->issuer,
            $this->audience,
            -10,
            -5,
            4096
        );

        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
			]
		]);

        $this->assertFalse($h->isAuthorized(new Request, $this->kirby->visitor()));
    }

    public function testMissingJwtHeader() : void 
    {        
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);

        $this->kirby = new App([
            'server' => []
        ]);

        $this->assertFalse($h->isAuthorized(new Request, $this->kirby->visitor()));
    }

    public function testInvalidJwt() : void 
    {        
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);

        $this->kirby = new App([
            'server' => []
        ]);

        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer 1234'
			]
		]);

        // Populate cache with valid JWKS
        $this->setupJWTAuthorization($this->issuer, $this->audience, 0, 5, 4096);

        $this->assertFalse($h->isAuthorized(new Request, $this->kirby->visitor(), false));
    }

    public function testInvalidJwt2() : void 
    {        
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);

        $this->kirby = new App([
            'server' => []
        ]);

        // Create new app environment with authorization header
        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => '1234'
			]
		]);

        // Populate cache with valid JWKS
        $this->setupJWTAuthorization($this->issuer, $this->audience, 0, 5, 4096);

        $this->assertFalse($h->isAuthorized(new Request, $this->kirby->visitor(), false));
    }

    public function testInvalidJwtAudience() : void 
    {        
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);
    
        $jwt = $this->setupJWTAuthorization(
            $this->issuer,
            'https://not-this-kirby-instance',
            0,
            5,
            4096
        );

        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
			]
		]);

        $this->assertFalse($h->isAuthorized(new Request, $this->kirby->visitor()));
    }

    public function testInvalidJwtIssuer() : void 
    {        
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);
    
        $jwt = $this->setupJWTAuthorization(
            'https://not-the-configured-kfm-instance',
            $this->audience,
            0,
            5,
            4096
        );

        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
			]
		]);

        $this->assertFalse($h->isAuthorized(new Request, $this->kirby->visitor()));
    }

    public function testEmptyJwks() : void 
    {
        $this->expectException(JwksException::class);

        $this->cache->set(RequestHandler::$JWKS_CACHE_KEY, [
            'keys' => []
        ], 1);

        $jwt = (new JwtCertificate)->issueJWT($this->issuer, $this->audience);
        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
			]
		]);

        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);
        $this->assertFalse($h->isAuthorized(new Request, $this->kirby->visitor()));
    }

    public function testInvalidJwks() : void 
    {
        $this->expectException(JwksException::class);

        $this->cache->set(RequestHandler::$JWKS_CACHE_KEY, [
            'not-keys' => []
        ], 1);

        $jwt = (new JwtCertificate)->issueJWT($this->issuer, $this->audience);
        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
			]
		]);

        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);
        $this->assertFalse($h->isAuthorized(new Request, $this->kirby->visitor()));
    }

    public function testJwksRequestMock() : void
    {
        $cert = new JwtCertificate();
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);

        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $cert->issueJWT($this->issuer, $this->audience)
            ],
            'options' => [
                'remote' => [
                    'test' => true,
                ]
            ]
		]);

        try {
            $h->isAuthorized(new Request, $this->kirby->visitor());
            $this->assertTrue(false);
        } catch(JwksException $e) {
            $this->assertStringContainsString("JWKS endpoint returned null", $e->getMessage());
        }
    }

    public function testIsAllowedIpWhitelistAllowAll() : void
    {
        $this->kirby = new App([
            'options' => [
                'philipptrenz.kfm-connector' => [
                    'ip_whitelist' => null
                ]
            ]
		]);
        $ipWhitelist = $this->kirby->option('philipptrenz.kfm-connector.ip_whitelist');
        $this->assertEquals($ipWhitelist, null);

        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, null, $ipWhitelist);

        foreach([
            '127.0.0.1',
            '172.0.0.2',
            '2001:db8:3c4d:15::1a2f:1a2b',
        ] as $ip) {
            $this->assertTrue($h->isAllowedIp($ip));
        }
    }

    public function testIsAllowedIpWhitelistDenyAll() : void
    {
        $this->kirby = new App([
            'options' => [
                'philipptrenz.kfm-connector' => [
                    'ip_whitelist' => []
                ]
            ]
		]);
        $ipWhitelist = $this->kirby->option('philipptrenz.kfm-connector.ip_whitelist');
        $this->assertEquals($ipWhitelist, []);

        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, null, $ipWhitelist);

        foreach([
            '127.0.0.1',
            '172.0.0.2',
            '2001:db8:3c4d:15::1a2f:1a2b',
        ] as $ip) {
            $this->assertFalse($h->isAllowedIp($ip));
        }
    }

    public function testIsAllowedIpWhitelistAllowSelection() : void
    {
        $this->kirby = new App([
            'options' => [
                'philipptrenz.kfm-connector' => [
                    'ip_whitelist' => [
                        '172.0.0.2',
                        '2001:db8:3c4d:15::1a2f:1a2b',
                    ]
                ]
            ]
		]);
        $ipWhitelist = $this->kirby->option('philipptrenz.kfm-connector.ip_whitelist');
        $this->assertEquals($ipWhitelist, [
            '172.0.0.2',
            '2001:db8:3c4d:15::1a2f:1a2b',
        ]);

        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, null, $ipWhitelist);

        foreach([
            '172.0.0.2',
            '2001:db8:3c4d:15::1a2f:1a2b',
        ] as $ip) {
            $this->assertTrue($h->isAllowedIp($ip));
        }

        foreach([
            '127.0.0.1',
            '2001:db8:3c4d:15::1a2f:1a2c',
        ] as $ip) {
            $this->assertFalse($h->isAllowedIp($ip));
        }
    }

    public function testIsAllowedIpWhitelistSingleIp() : void
    {
        $this->kirby = new App([
            'options' => [
                'philipptrenz.kfm-connector' => [
                    'ip_whitelist' => '172.0.0.2'
                ]
            ]
		]);
        $ipWhitelist = $this->kirby->option('philipptrenz.kfm-connector.ip_whitelist');
        $this->assertEquals($ipWhitelist, '172.0.0.2');

        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, null, $ipWhitelist);

        $this->assertTrue($h->isAllowedIp('172.0.0.2'));

        foreach([
            '127.0.0.1',
            '2001:db8:3c4d:15::1a2f:1a2c',
        ] as $ip) {
            $this->assertFalse($h->isAllowedIp($ip));
        }
    }

    public function testIssuerWithTrailingSlash1() : void
    {
        $jwt = $this->setupJWTAuthorization(
            'http://localhost:8000/',
            $this->audience,
            0,
            5,
            4096
        );
        
        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
            ],
		]);

        $h = new RequestHandler($this->cache, $this->audience, 'http://localhost:8000/', $this->cacheDuration);
        $this->assertTrue(
            $h->isAuthorized(new Request, $this->kirby->visitor())
        );

        $h2 = new RequestHandler($this->cache, $this->audience, 'http://localhost:8000', $this->cacheDuration);
        $this->assertTrue(
            $h2->isAuthorized(new Request, $this->kirby->visitor())
        );
    }

    public function testIssuerWithTrailingSlash2() : void
    {
        $jwt = $this->setupJWTAuthorization(
            'http://localhost:8000',
            $this->audience,
            0,
            5,
            4096
        );
        
        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
            ],
		]);

        $h = new RequestHandler($this->cache, $this->audience, 'http://localhost:8000/', $this->cacheDuration);
        $this->assertTrue(
            $h->isAuthorized(new Request, $this->kirby->visitor())
        );

        $h2 = new RequestHandler($this->cache, $this->audience, 'http://localhost:8000', $this->cacheDuration);
        $this->assertTrue(
            $h2->isAuthorized(new Request, $this->kirby->visitor())
        );
    }

    public function testAudienceWithTrailingSlash1() : void
    {
        $jwt = $this->setupJWTAuthorization(
            $this->issuer,
            'http://localhost:9000/',
            0,
            5,
            4096
        );
        
        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
            ],
		]);

        $h = new RequestHandler($this->cache, 'http://localhost:9000/', $this->issuer, $this->cacheDuration);
        $this->assertTrue(
            $h->isAuthorized(new Request, $this->kirby->visitor())
        );

        $h2 = new RequestHandler($this->cache, 'http://localhost:9000', $this->issuer, $this->cacheDuration);
        $this->assertTrue(
            $h2->isAuthorized(new Request, $this->kirby->visitor())
        );
    }

    public function testAudienceWithTrailingSlash2() : void
    {
        $jwt = $this->setupJWTAuthorization(
            $this->issuer,
            'http://localhost:9000',
            0,
            5,
            4096
        );
        
        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
            ],
		]);

        $h = new RequestHandler($this->cache, 'http://localhost:9000/', $this->issuer, $this->cacheDuration);
        $this->assertTrue(
            $h->isAuthorized(new Request, $this->kirby->visitor())
        );

        $h2 = new RequestHandler($this->cache, 'http://localhost:9000', $this->issuer, $this->cacheDuration);
        $this->assertTrue(
            $h2->isAuthorized(new Request, $this->kirby->visitor())
        );
    }

    public function testRateLimitExceeded() : void
    {
        $cert = new JwtCertificate();

        // Populate cache with jwks
        $this->cache->set(RequestHandler::$JWKS_CACHE_KEY, JwtCertificate::toJWKS($cert));

        $cert2 = new JwtCertificate();
        $jwt = $cert2->issueJWT($this->issuer, $this->audience);

        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
            ],
		]);

        $h = new RequestHandler($this->cache, 'http://localhost:9000/', $this->issuer, $this->cacheDuration);
        try {
            $h->isAuthorized(new Request, $this->kirby->visitor());
            $this->assertTrue(false);
        } catch(JwksException $e) {
            // Expect connection error
            $this->assertTrue(true);
        }

        // Check if rate limit cache value is set correctly
        $this->assertEquals(1, $this->cache->get(RequestHandler::$RATE_LIMIT_CACHE_KEY));
        $initalExpiresAt = $this->cache->expires(RequestHandler::$RATE_LIMIT_CACHE_KEY);
        $this->assertGreaterThanOrEqual(time() + 60, $initalExpiresAt);

        for($i=2; $i<=10; $i++) {

            // Re-populate cache with jwks
            $this->cache->set(RequestHandler::$JWKS_CACHE_KEY, JwtCertificate::toJWKS($cert));

            try {
                $h->isAuthorized(new Request, $this->kirby->visitor());
                $this->assertTrue(false);
            } catch(JwksException $e) {
                // Expect connection error
                $this->assertTrue(true);
            }

            // Check if rate limit cache value is set correctly
            $this->assertEquals($i, $this->cache->get(RequestHandler::$RATE_LIMIT_CACHE_KEY));
            $expiresAt = $this->cache->expires(RequestHandler::$RATE_LIMIT_CACHE_KEY);
            $this->assertGreaterThanOrEqual(time() + 60, $expiresAt);
            $this->assertEquals($initalExpiresAt, $expiresAt);
        }

        // Re-populate cache with jwks
        $this->cache->set(RequestHandler::$JWKS_CACHE_KEY, JwtCertificate::toJWKS($cert));

        // Assert, that isAuthorized() returns false without doing JWKS lookup
        $this->assertFalse(
            $h->isAuthorized(new Request, $this->kirby->visitor())
        );

    }

    public function testRateLimitCacheCounterReset() : void
    {
        $cert = new JwtCertificate();

        // Populate cache with jwks
        $this->cache->set(RequestHandler::$JWKS_CACHE_KEY, JwtCertificate::toJWKS($cert));

        $cert2 = new JwtCertificate();
        $jwt = $cert2->issueJWT($this->issuer, $this->audience);

        $this->kirby = new App([
			'server' => [
				'HTTP_AUTHORIZATION' => 'Bearer ' . $jwt
            ],
		]);

        $h = new RequestHandler($this->cache, 'http://localhost:9000/', $this->issuer, $this->cacheDuration);
        try {
            $h->isAuthorized(new Request, $this->kirby->visitor());
            $this->assertTrue(false);
        } catch(JwksException $e) {
            // Expect connection error
            $this->assertTrue(true);
        }

        // Check if rate limit cache value is set correctly
        $this->assertEquals(1, $this->cache->get(RequestHandler::$RATE_LIMIT_CACHE_KEY));
        $initalExpiresAt = $this->cache->expires(RequestHandler::$RATE_LIMIT_CACHE_KEY);
        $this->assertGreaterThanOrEqual(time() + 60, $initalExpiresAt);

        for($i=2; $i<=7; $i++) {

            sleep(10);

            // Re-populate cache with jwks
            $this->cache->set(RequestHandler::$JWKS_CACHE_KEY, JwtCertificate::toJWKS($cert));

            try {
                $h->isAuthorized(new Request, $this->kirby->visitor());
                $this->assertTrue(false);
            } catch(JwksException $e) {
                // Expect connection error
                $this->assertTrue(true);
            }

            $expiresAt = $this->cache->expires(RequestHandler::$RATE_LIMIT_CACHE_KEY);
            if ($initalExpiresAt > time()) {    // within first minote
                $this->assertEquals($i, $this->cache->get(RequestHandler::$RATE_LIMIT_CACHE_KEY));
                $this->assertEquals($initalExpiresAt, $expiresAt);
            } else {                            // after one minute
                $this->assertLessThan(6, $this->cache->get(RequestHandler::$RATE_LIMIT_CACHE_KEY));
                $this->assertGreaterThanOrEqual($initalExpiresAt + 60, $expiresAt);
            }
        }

    }

}