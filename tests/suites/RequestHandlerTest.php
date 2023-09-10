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

}