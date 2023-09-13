<?php declare(strict_types=1);

namespace PhilippTrenz\KFMConnector;

use Exception;
use Kirby\Cms\App;
use DomainException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Kirby\Cache\Cache;
use Kirby\Http\Remote;
use Kirby\Http\Request;
use Kirby\Http\Visitor;
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

    /**
     * Identifier string to whom a JWT token is addressed,
     * expected to be the base URL of the Kirby installation
     * @var string
     */
    private string $audience;

    /**
     * Identification string from whom the JWT token was
     * issued, expected to be the Kirby Fleet Manager base URL
     * @var string
     * @author Philipp Trenz
     */
    private string $issuer;

    /**
     * URL to the external JWKS
     * @var string
     */
    private string $jwksUrl;

    /**
     * Lifetime of the JWKS cache in minutes
     * @var int
     */
    private int $jwksCacheDuration;

    /**
     * List of IPs which are allowed to request data;
     * if is not null, all requests from other IPs get denied
     * @var array|null
     * @author Philipp Trenz
     */
    private array|null $ipWhitelist;

    /**
     * Constructor
     * @param \Kirby\Cache\Cache $cache
     * @param string $audience
     * @param string $issuer
     * @param int|null $jwksCacheDuration
     */
    public function __construct(Cache $cache, string $audience, string $issuer, int|null $jwksCacheDuration=null, string|array|null $ipWhitelist=null) {
        $this->cache             = $cache;
        $this->audience          = rtrim($audience, '/');
        $this->issuer            = rtrim($issuer, '/');
        $this->jwksUrl           = rtrim($this->issuer, '/') . '/api/jwks';
        $this->jwksCacheDuration = $jwksCacheDuration ?? 60*24*3;  // fallback: 3 days

        if (is_string($ipWhitelist)) $this->ipWhitelist = [$ipWhitelist];
        else $this->ipWhitelist = $ipWhitelist;
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

    public function isAllowedIp(string $ip) : bool
    {
        return $this->ipWhitelist === null ||
               in_array($ip, $this->ipWhitelist) === true;
    }

    /**
     * Invalidates JWKS cache
     * @return void
     */
    private function invalidateJwksCache() : void
    {
        $this->cache->remove(self::$JWKS_CACHE_KEY);
    }

    /**
     * Parses a raw JSON web key set array into a Key array
     * @param array $jwks
     * @throws \PhilippTrenz\KFMConnector\JwksException
     * @return \Firebase\JWT\Key[]
     */
    private function parseKeySet(array $jwks) : array
    {
        try {
            return JWK::parseKeySet($jwks);
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
    }

    /**
     * Retrieves a Key array from cache or, if cache
     * is empty, from external JWKS store
     * @throws \PhilippTrenz\KFMConnector\JwksException
     * @return \Firebase\JWT\Key[]
     */
    private function getKeySet() : array
    {
        $jwks = $this->cache->get(self::$JWKS_CACHE_KEY, null);

        // If cache is empty
        if ($jwks === null) {
            try {
                $response = Remote::get($this->jwksUrl, [
                    'headers' => ['Content-Type' => 'application/json']
                ]);
            } catch (Exception $e) {
                throw new JwksException($e->getMessage());
            }

            if ($response->content() === null)
                throw new JwksException("JWKS endpoint returned null");

            // Update cache with fetched JSON web key set
            $jwks = $response->json();
            $this->cache->set(
                self::$JWKS_CACHE_KEY,
                $jwks,
                $this->jwksCacheDuration
            );
        }

        return $this->parseKeySet($jwks);
    }

    /**
     * Checks if key id is in Keys array
     * @param string $kid
     * @param \Firebase\JWT\Key[] $keySet
     * @return bool
     */
    private function hasKey(string $kid, array $keySet) : bool
    {
        return array_key_exists($kid, $keySet);
    }

    /**
     * Validates the JWT token against a public key from cache
     * or, if cache is empty, from external JWKS store
     * @param string $jwt
     * @param bool $isRetry
     * @return bool
     */
    private function isJWTValid(string $jwt, bool $isRetry=false): bool
    {
        $payload = null;
        $keySet = $this->getKeySet();

        try {
            $payload = JWT::decode($jwt, $keySet);
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
            if ($payload !== null && $isRetry === false && $this->hasKey($payload->kid, $keySet) === false) {
                // Invalidate JWKS cache and retry
                $this->invalidateJwksCache();
                return $this->isJWTValid($jwt, true);
            }
            return false;
        }

        return rtrim($payload->iss, '/') === $this->issuer &&
               rtrim($payload->aud, '/') === $this->audience;
    }

    /**
     * Validates the JWT token contained in the Authorization header 
     * to determine whether an incoming HTTP request is authorized
     * @param \Kirby\Http\Request $request
     * @param bool $autoRefreshJwksCache
     * @return bool
     */
    public function isAuthorized(Request $request, Visitor $visitor, bool $autoRefreshJwksCache=true): bool
    {
        if (
            $this->isAllowedIp($visitor->ip()) &&
            $authHeader = $request->header('Authorization')
        ) {
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
        $cache         = $kirby->cache('philipptrenz.kfm-connector');
        $audience      = $kirby->url();
        $issuer        = $kirby->option('philipptrenz.kfm-connector.issuer', null);
        $cacheDuration = $kirby->option('philipptrenz.kfm-connector.jwks_cache_duration', null);
        $ipWhitelist   = $kirby->option('philipptrenz.kfm-connector.ip_whitelist', null);

        $request = $kirby->request();
        $visitor = $kirby->visitor();
        
        $handler = new RequestHandler($cache, $audience, $issuer, $cacheDuration, $ipWhitelist);
        try {
            if ($issuer === null || $handler->isAuthorized($request, $visitor) !== true) {
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
        return Response::json((new KirbyStatus)->getStatus());
    }
}