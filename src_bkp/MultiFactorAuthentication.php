<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Authentication\MultiFactor;
use Lucinda\WebSecurity\Authentication\MultiFactor\ResultStatus as MfaStatus;
use Lucinda\WebSecurity\Authentication\Result;

/**
 * Performs multifactor authentication by calling the external driver
 */
class MultiFactorAuthentication
{
    /**
     * Composes and throws a security packet to be caught externally
     * 
     * @param  int|string $userID
     * @param  Request $request     
     * @param  MultiFactor $multiFactorDriver
     * @throws SecurityPacket
     */
    public function __construct(int|string $userID, Request $request, MultiFactor $multiFactorDriver)
    {
        $mfaResult = $multiFactorDriver->verify($userID, $request);
        if (in_array($mfaResult->getStatus(), [
            MfaStatus::REQUIRED,
            MfaStatus::SETUP_REQUIRED,
            MfaStatus::THROTTLED
            ])) {
            $this->compose($userID, $mfaResult, $request);
        }
    }

    /**
     * Composes and throws a security packet to be caught externally
     * 
     * @param  int|string $userID
     * @param  Result  $mfaResult
     * @param  Request $request     
     * @return void
     * @throws MultiFactorSecurityPacket
     */
    private function compose(int|string $userID, Result $mfaResult, Request $request)
    {
        $transport = new MultiFactorSecurityPacket();
        $transport->setUserID($userID);
        $transport->setCallback($request->getContextPath()."/".$mfaResult->getCallbackURI());
        $transport->setStatus($mfaResult->getStatus());
        if ($timePenalty = $mfaResult->getTimePenalty()) {
            $transport->setTimePenalty($timePenalty);
        }
        throw $transport;
    }
}