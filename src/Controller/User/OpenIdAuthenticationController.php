<?php

namespace App\Controller\User;

use App\Command\CommandDispatcherTrait;
use App\Entity\User\Organization;
use App\Entity\User\User;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Symfony\Component\Routing\Annotation\Route;
use League\OAuth2\Client\Provider\GenericProvider;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\PreAuthenticatedToken;

/**
 * OAuth Service controller.
 *
 * @Route("/login")
 */
class OpenIdAuthenticationController extends AbstractController
{
    use CommandDispatcherTrait;

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
                                string $oauthScopes = 'openid email roles', string $oauthRolesField = 'roles',
                                string $oauthSuperAdminRoles = '', string $oauthSuperEditorRoles = '',
                                string $oauthAdminRoles = '', string $oauthEditorRoles = '')
    {
        $this->oauthClientId = $oauthClientId;
        $this->oauthClientSecret = $oauthClientSecret;
        $this->oauthRedirectUri = $oauthRedirectUri;
        $this->oauthAuthorizeUrl = $oauthAuthorizeUrl;
        $this->oauthAccessTokenUrl = $oauthAccessTokenUrl;
        $this->oauthUserInfoUrl = $oauthUserInfoUrl;
        $this->oauthScopes = $oauthScopes;
        $this->oauthRolesField = $oauthRolesField;
        $this->oauthSuperAdminRoles = $oauthSuperAdminRoles;
        $this->oauthSuperEditorRoles = $oauthSuperEditorRoles;
        $this->oauthAdminRoles = $oauthAdminRoles;
        $this->oauthEditorRoles = $oauthEditorRoles;
    }

    /**
     * Complete login
     *
     * @Route("/openid", methods={"GET"}, name="openid_login")
     *
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     *
     * @throws \UnexpectedValueException
     */
    public function oauthLogin(Request $request, SessionInterface $session): Response
    {
        try {
            $provider = $this->getProvider();

            $code = $request->query->get('code');
            $state = $request->query->get('state');
            $error = $request->query->get('error');

            if ($error) {
                throw new \Exception($request->query->get('error_description'));
            }

            if (!isset($code)) {
                // If we don't have an authorization code then get one
                $authUrl = $provider->getAuthorizationUrl();
                // Set a state to to validate
                $session->set('oauth2state', $provider->getState());

                return $this->redirect($authUrl);
            }

            // Validate oauth token state
            if (empty($state) || ($state !== $session->get('oauth2state'))) {
                $session->remove('oauth2state');
                throw new \UnexpectedValueException('Invalid state.');
            }

            // Try to get an access token (using the authorization code grant)
            $token = $provider->getAccessToken('authorization_code', [
                'code' => $code,
            ]);

            // Find existing user by email
            $details = $provider->getResourceOwner($token)->toArray();
            $email = $details['email'];

            $em = $this->getDoctrine()->getManager();
            $user = $em->getRepository(User::class)->findOneBy([
                'username' => $email
            ]);

            if (!$user) {
                $organization = $em->getRepository(Organization::class)->find(1);
                $user = (new User())
                    ->setUsername($email)
                    ->setStatus(User::ACTIVE)
                    ->setOrg($organization);
            }

            // Update roles every time
            $roles = $details[$this->oauthRolesField] ?? [];
            $user->setRoles($this->mapRoles($roles));
            $em->persist($user);
            $em->flush();


            $authToken = new PreAuthenticatedToken($user, ['token' => $token->getToken()], 'oauth', $user->getRoles());
            $this->container->get('security.token_storage')->setToken($authToken);

            return $this->redirectToRoute('lsdoc_index');
        }
        catch(IdentityProviderException $ex) {
            return $this->render('framework/oauth/error.twig', [
                'error' => $ex->getMessage(),
                'error_description' => json_encode($ex->getResponseBody()),
                'retry_url' => $this->generateUrl('openid_login'),
            ]);
        }
        catch(\Exception $ex) {
            return $this->render('framework/oauth/error.twig', [
                'error' => get_class($ex),
                'error_description' => $ex->getMessage(),
                'retry_url' => $this->generateUrl('openid_login'),
            ]);
        }
    }

    protected function getProvider()
    {
        if (!empty($this->oauthRedirectUri)) {
            $redirectUri = $this->oauthRedirectUri;
        }
        if (empty($redirectUri)) {
            $redirectUri = $this->generateUrl(
                'openid_login',
                [],
                UrlGeneratorInterface::ABSOLUTE_URL
            );
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

    protected function mapRoles(array $roles)
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
}
