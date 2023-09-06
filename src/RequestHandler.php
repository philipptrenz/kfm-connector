<?php declare(strict_types=1);

namespace PhilippTrenz\KFMConnector;

use DomainException;
use InvalidArgumentException;
use UnexpectedValueException;

use Kirby\Cms\App;
use Kirby\Http\Request;
use Kirby\Http\Response;
use Kirby\Http\Remote;
use Kirby\Cache\Cache;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;

JWT::$leeway = 60;  // in seconds

final class RequestHandler {

    public static string $JWKS_CACHE_KEY = 'jwks';

    private Cache $cache;

    private string $audience;
    private string $issuer;
    private string $jwksUrl;
    private int $jwksCacheDuration;

    public function __construct(Cache $cache, string $audience, string $issuer, int|null $jwksCacheDuration=null) {
        $this->cache             = $cache;
        $this->audience          = $audience;
        $this->issuer            = $issuer;
        $this->jwksUrl           = rtrim($this->issuer, '/') . '/api/jwks';
        $this->jwksCacheDuration = $jwksCacheDuration ?? 60*24*3;  // fallback: 3 days
    }

    public function getAudience() : string 
    {
        return $this->audience;
    }

    public function getIssuer() : string 
    {
        return $this->issuer;
    }

    public function getJwksUrl() : string 
    {
        return $this->jwksUrl;
    }

    public function getJwksCacheDuration() : int
    {
        return $this->jwksCacheDuration;
    }

    private function invalidateJwksCache()
    {
        $this->cache->remove(self::$JWKS_CACHE_KEY);
    }

    private function getJwks(): array|null
    {
        $jwksUrl = $this->jwksUrl;
        $jwksCache = $this->cache->getOrSet(self::$JWKS_CACHE_KEY, function() use ($jwksUrl) {
            // Fetch JWKS
            return Remote::get($jwksUrl, [
                'headers' => [
                    'Content-Type' => 'application/json',
                ],
            ])->json();
        }, $this->jwksCacheDuration);

        return $jwksCache;
    }

    private function isJWTValid(string $jwt, bool $isRetry = false): bool
    {   
        $audience = $this->audience;
        try {
            $jwks = $this->getJwks();  // ignore cache on retry
            $payload = JWT::decode($jwt, JWK::parseKeySet($jwks));
            $isAuthorized = $payload->iss === $this->issuer && $payload->aud === $audience;

            return $isAuthorized;
        } catch (InvalidArgumentException $e) {
            // provided key/key-array is empty or malformed.
            return false;
        } catch (DomainException $e) {
            // provided algorithm is unsupported OR
            // provided key is invalid OR
            // unknown error thrown in openSSL or libsodium OR
            // libsodium is required but not available.
            return false;
        } catch (SignatureInvalidException $e) {
            // provided JWT signature verification failed.
            return false;
        } catch (BeforeValidException $e) {
            // provided JWT is trying to be used before "nbf" claim OR
            // provided JWT is trying to be used before "iat" claim.
            return false;
        } catch (ExpiredException $e) {
            // provided JWT is trying to be used after "exp" claim.
            return false;
        } catch (UnexpectedValueException $e) {
            // provided JWT is malformed OR
            // provided JWT is missing an algorithm / using an unsupported algorithm OR
            // provided JWT algorithm does not match provided key OR
            // provided key ID in key/key-array is empty or invalid.

            if ($isRetry === false) {  // prevent recursion loop
                // if key ID is missing in JWKS, the cached JWKS might be outdated
                // therefore, invalidate JWKS cache and validate again

                // TODO: Limit number of retries per time unit

                $this->invalidateJwksCache();
                return $this->isJWTValid($jwt, true);
            }

            return false;
        }
    }

    public function isAuthorized(Request $request, bool $autorefreshJwksCache=true): bool 
    {
        if ($authHeader = $request->header('Authorization')) {
            $jwt = str_replace('Bearer ', '', $authHeader);
            return $this->isJWTValid($jwt, !$autorefreshJwksCache) === true;
        }
        return false;
    }

    public static function process(): Response 
    {
        $kirby         = App::instance();
        $cache         = $kirby->cache('philipptrenz.kirby-fleet-manager-connector');
        $audience      = $kirby->site()->url();
        $issuer        = $kirby->option('philipptrenz.kirby-fleet-manager-connector.issuer', null);
        $cacheDuration = $kirby->option('philipptrenz.kirby-fleet-manager-connector.jwksCacheDuration', null);

        $request = $kirby->request();
        
        $handler = new RequestHandler($cache, $audience, $issuer, $cacheDuration);
        if ($issuer === null || $handler->isAuthorized($request) !== true) {
            return new Response([
                'code' => 401,
                'message' => 'Not authorized'
            ]);
        }
        return Response::json((new Status)->getStatus());
    }
}