<?php

namespace App\Controller\User;

use App\Command\CommandDispatcherTrait;
use App\Entity\User\Organization;
use App\Entity\User\User;
use App\Service\OpenIDAuthenticationService;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Symfony\Component\Routing\Annotation\Route;
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
     * @var OpenIDAuthenticationService
     */
    private OpenIDAuthenticationService $service;

    public function __construct(OpenIDAuthenticationService $service)
    {
        $this->service = $service;
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
            $user->setRoles($this->service->getRolesFromToken($details));
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
        $redirectUri = $this->generateUrl(
            'openid_login',
            [],
            UrlGeneratorInterface::ABSOLUTE_URL
        );

        return $this->service->getProvider($redirectUri);
    }
}
