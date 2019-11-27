<?php
namespace Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\Authorization\AuthorizationException;
use Lucinda\WebSecurity\Authorization\AuthorizationResult;
use Lucinda\WebSecurity\Authorization\AuthorizationResultStatus;

/**
 * Encapsulates request authorization via XML that must have routes configured as:
 * <routes>
 * 	<route url="{PAGE_TO_AUTHORIZE" access="ROLE_GUEST|ROLE_USER" ... />
 * 	...
 * </routes>
 */
class XMLAuthorization
{
    private $loggedInFailureCallback;
    private $loggedOutFailureCallback;
    
    /**
     * Creates an object
     *
     * @param string $loggedInFailureCallback
     * @param string $loggedOutFailureCallback
     */
    public function __construct(string $loggedInFailureCallback, string $loggedOutFailureCallback): void
    {
        $this->loggedInFailureCallback = $loggedInFailureCallback;
        $this->loggedOutFailureCallback = $loggedOutFailureCallback;
    }
    
    /**
     * Performs an authorization task.
     *
     * @param \SimpleXMLElement $xml
     * @param string $routeToAuthorize
     * @param integer $userID
     * @param UserAuthorizationRoles $userAuthorizationRoles
     * @throws AuthorizationException If route is misconfigured.
     * @return AuthorizationResult
     */
    public function authorize(\SimpleXMLElement $xml, string $routeToAuthorize, int $userID=0, UserAuthorizationRoles $userAuthorizationRoles): AuthorizationResult
    {
        $status = 0;
        $callbackURI = "";
        
        // check if user is authenticated
        $isUserGuest = ($userID==0?true:false);
        
        // get user roles
        $userRoles = $userAuthorizationRoles->getRoles($userID);
        
        // get page roles
        $pageDAO = new PageAuthorizationXML($xml);
        $pageRoles = $pageDAO->getRoles($routeToAuthorize);
        if (empty($pageRoles)) {
            $status = AuthorizationResultStatus::NOT_FOUND;
            $callbackURI = ($isUserGuest?$this->loggedOutFailureCallback:$this->loggedInFailureCallback);
        } else {
            // compare user roles to page roles
            $allowed = false;
            foreach ($pageRoles as $role) {
                if (in_array($role, $userRoles)) {
                    $allowed= true;
                    break;
                }
            }
            
            // now perform rights check
            if ($allowed) {
                $status = AuthorizationResultStatus::OK;
            } elseif ($isUserGuest) {
                $status = AuthorizationResultStatus::UNAUTHORIZED;
                $callbackURI = $this->loggedOutFailureCallback;
            } else {
                $status = AuthorizationResultStatus::FORBIDDEN;
                $callbackURI = $this->loggedInFailureCallback;
            }
        }
        
        return new AuthorizationResult($status, $callbackURI);
    }
}
