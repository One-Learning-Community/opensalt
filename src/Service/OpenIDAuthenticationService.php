<?php

namespace App\Service;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use League\OAuth2\Client\Provider\GenericProvider;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class OpenIDAuthenticationService {
    /**
     * @var string
     */
    private $oauthClientId;

    /**
     * @var string
     */
    private $oauthClientSecret;

    /**
     * @var string
     */
    private $oauthRedirectUri;

    /**
     * @var string
     */
    private $oauthAuthorizeUrl;

    /**
     * @var string
     */
    private $oauthAccessTokenUrl;

    /**
     * @var string
     */
    private $oauthUserInfoUrl;

    /**
     * @var string
     */
    private $oauthJwkUrl;

    /**
     * @var string
     */
    private $oauthScopes;

    /**
     * @var string
     */
    private $oauthRolesField;

    /**
     * @var string
     */
    private $oauthSuperAdminRoles;

    /**
     * @var string
     */
    private $oauthSuperEditorRoles;

    /**
     * @var string
     */
    private $oauthAdminRoles;

    /**
     * @var string
     */
    private $oauthEditorRoles;


    public function __construct(string $oauthClientId = null, string $oauthClientSecret = null, string $oauthRedirectUri = null,
                                string $oauthAuthorizeUrl = null, string $oauthAccessTokenUrl = null, string $oauthUserInfoUrl = null,
                                string $oauthJwkUrl = null, string $oauthScopes = 'openid email roles', string $oauthRolesField = 'roles',
                                string $oauthSuperAdminRoles = '', string $oauthSuperEditorRoles = '',
                                string $oauthAdminRoles = '', string $oauthEditorRoles = '')
    {
        $this->oauthClientId = $oauthClientId;
        $this->oauthClientSecret = $oauthClientSecret;
        $this->oauthRedirectUri = $oauthRedirectUri;
        $this->oauthAuthorizeUrl = $oauthAuthorizeUrl;
        $this->oauthAccessTokenUrl = $oauthAccessTokenUrl;
        $this->oauthUserInfoUrl = $oauthUserInfoUrl;
        $this->oauthJwkUrl = $oauthJwkUrl;
        $this->oauthScopes = $oauthScopes;
        $this->oauthRolesField = $oauthRolesField;
        $this->oauthSuperAdminRoles = $oauthSuperAdminRoles;
        $this->oauthSuperEditorRoles = $oauthSuperEditorRoles;
        $this->oauthAdminRoles = $oauthAdminRoles;
        $this->oauthEditorRoles = $oauthEditorRoles;
    }

    public function mapRoles(array $roles)
    {
        $roleMap = [
            'ROLE_EDITOR' => $this->oauthEditorRoles,
            'ROLE_ADMIN' => $this->oauthAdminRoles,
            'ROLE_SUPER_EDITOR' => $this->oauthSuperEditorRoles,
            'ROLE_SUPER_USER' => $this->oauthSuperAdminRoles,
        ];

        $mappedRoles = [
            'ROLE_USER', // Default
        ];

        foreach($roleMap as $userRole => $mappableRoles)
        {
            if ($mappableRoles && array_intersect($roles, explode(' ', $mappableRoles)))
            {
                $mappedRoles[] = $userRole;
            }
        }

        return $mappedRoles;
    }

    public function getProvider($redirectUri = null)
    {
        if (!empty($this->oauthRedirectUri)) {
            $redirectUri = $this->oauthRedirectUri;
        }

        return new GenericProvider([
            'clientId'     => $this->oauthClientId,
            'clientSecret' => $this->oauthClientSecret,
            'redirectUri'  => $redirectUri,
            'urlAuthorize' => $this->oauthAuthorizeUrl,
            'urlAccessToken' => $this->oauthAccessTokenUrl,
            'urlResourceOwnerDetails' => $this->oauthUserInfoUrl,
            'scopes' => $this->oauthScopes
        ]);
    }

    public function getRolesFromToken($token)
    {
        if (!is_array($token))
        {
            $token = (array) $token;
        }

        $roles = $token[$this->oauthRolesField] ?? [];
        return $this->mapRoles($roles);
    }

    public function getTokenDetails($token)
    {
        $keys = json_decode(file_get_contents($this->oauthJwkUrl), true);
        $keySet = JWK::parseKeySet($keys);
        $algSet = array_map(fn($key) => $key['alg'], $keys['keys']);
        return JWT::decode($token, $keySet, $algSet);
    }
}