<?php
use Kirby\Cms\App;
use Kirby\Cache\Cache;
use Kirby\Http\Request;
use PHPUnit\Framework\TestCase;
use PhilippTrenz\KFMConnector\RequestHandler;
use PhilippTrenz\KFMConnector\JWTCertificate;

final class RequestHandlerTest extends TestCase {

    private App $kirby;
    private Cache $cache;
    private string $audience;
    private string $issuer;
    private int|null $cacheDuration;

    protected function setUp() : void
    {        
        $this->kirby = kirby();

        $this->cache         = $this->kirby->cache('philipptrenz.kirby-fleet-manager-connector');
        $this->audience      = $this->kirby->site()->url();
        $this->issuer        = $this->kirby->option('philipptrenz.kirby-fleet-manager-connector.issuer', null);
        $this->cacheDuration = $this->kirby->option('philipptrenz.kirby-fleet-manager-connector.jwksCacheDuration', null);

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
        $cert = new JWTCertificate($certBits);
        
        // Populate cache with jwks
        $this->cache->set(RequestHandler::$JWKS_CACHE_KEY, JWTCertificate::toJWKS($cert), 1);

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

        $this->assertTrue($h->isAuthorized($request));
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

        $this->assertFalse($h->isAuthorized(new Request));
    }

    public function testMissingJwtHeader() : void 
    {        
        $h = new RequestHandler($this->cache, $this->audience, $this->issuer, $this->cacheDuration);

        $this->kirby = new App([
            'server' => []
        ]);

        $this->assertFalse($h->isAuthorized(new Request));
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

        $this->assertFalse($h->isAuthorized(new Request, false));
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

        $this->assertFalse($h->isAuthorized(new Request, false));
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

        $this->assertFalse($h->isAuthorized(new Request));
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

        $this->assertFalse($h->isAuthorized(new Request));
    }

}