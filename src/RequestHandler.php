<?php declare(strict_types=1);

namespace PhilippTrenz\KFMConnector;

use Kirby\Cms\App;
use DomainException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Kirby\Cache\Cache;
use Kirby\Http\Remote;
use Kirby\Http\Request;
use Kirby\Http\Response;
use InvalidArgumentException;
use UnexpectedValueException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\SignatureInvalidException;

JWT::$leeway = 60;  // in seconds

/**
 * RequestHandler class
 * 
 * Validates authorization header for a Kirby HTTP request
 * based on external JSON Web Key Set (JWKS).
 * 
 * @author Philipp Trenz
 * @copyright (c) 2023
 */
final class RequestHandler {

    public static string $JWKS_CACHE_KEY = 'jwks';

    private Cache $cache;

    private string $audience;
    private string $issuer;
    private string $jwksUrl;
    private int $jwksCacheDuration;

    /**
     * Constructor
     * @param \Kirby\Cache\Cache $cache
     * @param string $audience
     * @param string $issuer
     * @param int|null $jwksCacheDuration
     */
    public function __construct(Cache $cache, string $audience, string $issuer, int|null $jwksCacheDuration=null) {
        $this->cache             = $cache;
        $this->audience          = $audience;
        $this->issuer            = $issuer;
        $this->jwksUrl           = rtrim($this->issuer, '/') . '/api/jwks';
        $this->jwksCacheDuration = $jwksCacheDuration ?? 60*24*3;  // fallback: 3 days
    }

    /**
     * Returns audience property
     * @return string
     */
    public function getAudience() : string 
    {
        return $this->audience;
    }

    /**
     * Returns issuer property
     * @return string
     */
    public function getIssuer() : string 
    {
        return $this->issuer;
    }

    /**
     * Returns URL to JSON Web Key Set (JWKS) based on issuer URL
     * @return string
     */
    public function getJwksUrl() : string 
    {
        return $this->jwksUrl;
    }

    /**
     * Returns configured minutes until expiration of JWKS cache
     * @return int
     */
    public function getJwksCacheDuration() : int
    {
        return $this->jwksCacheDuration;
    }

    /**
     * Invalidates JWKS cache
     * @return void
     */
    private function invalidateJwksCache()
    {
        $this->cache->remove(self::$JWKS_CACHE_KEY);
    }

    /**
     * Retrieves JWKS from cache, if existant, 
     * otherwise fetches it via HTTP request from issuer
     * @return array|null
     */
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

    /**
     * Summary of hasKey
     * @param string $kid
     * @param \Firebase\JWT\Key[] $keySet
     * @return bool
     */
    private function hasKey(string $kid, array $keySet) : bool
    {
        return array_key_exists($kid, $keySet);
    }

    /**
     * Summary of isJWTValid
     * @param string $jwt
     * @param bool $isRetry
     * @throws \PhilippTrenz\KFMConnector\JwksException
     * @return bool
     */
    private function isJWTValid(string $jwt, bool $isRetry=false): bool
    {   
        $audience = $this->audience;

        try {
            $jwks = $this->getJwks();
            $keySet = JWK::parseKeySet($jwks);
        } catch (InvalidArgumentException $e) {
            // provided JWK Set is empty OR
            // an included JWK is empty
            throw new JwksException($e->getMessage());
        } catch (UnexpectedValueException $e) {
            // Provided JWK Set was invalid OR
            // an included JWK is invalid
            throw new JwksException($e->getMessage());
        } catch (DomainException $e) {
            // OpenSSL failure
            throw new JwksException($e->getMessage());
        }

        try {
            $payload = JWT::decode($jwt, $keySet);
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
            // provided key id in key/key-array is empty or invalid.

            // if key id is missing in JWKS, the cached JWKS might be outdated
            if ($isRetry === false && $this->hasKey($payload->kid, $keySet) === false) {
                // Invalidate JWKS cache and retry
                $this->invalidateJwksCache();
                return $this->isJWTValid($jwt, true);
            }
            return false;
        }
    }

    /**
     * Validates the JWT token contained in the Authorization header 
     * to determine whether an incoming HTTP request is authorized
     * @param \Kirby\Http\Request $request
     * @param bool $autoRefreshJwksCache
     * @return bool
     */
    public function isAuthorized(Request $request, bool $autoRefreshJwksCache=true): bool 
    {
        if ($authHeader = $request->header('Authorization')) {
            $jwt = str_replace('Bearer ', '', $authHeader);
            return $this->isJWTValid($jwt, !$autoRefreshJwksCache) === true;
        }
        return false;
    }

    /**
     * Convenience method to instantiate a RequestHandler based on the plugin 
     * configuration and return an appropriate response.
     * @return \Kirby\Http\Response
     */
    public static function process(): Response 
    {
        $kirby         = App::instance();
        $cache         = $kirby->cache('philipptrenz.kirby-fleet-manager-connector');
        $audience      = $kirby->site()->url();
        $issuer        = $kirby->option('philipptrenz.kirby-fleet-manager-connector.issuer', null);
        $cacheDuration = $kirby->option('philipptrenz.kirby-fleet-manager-connector.jwksCacheDuration', null);

        $request = $kirby->request();
        
        $handler = new RequestHandler($cache, $audience, $issuer, $cacheDuration);
        try {
            if ($issuer === null || $handler->isAuthorized($request) !== true) {
                return new Response([
                    'code' => 401,
                    'message' => 'Not authorized'
                ]);
            }
        } catch (JwksException $e) {
            return new Response([
                'code' => 503,
                'message' => 'Service unavailable'
            ]);
        }
        return Response::json((new Status)->getStatus());
    }
}