<?php

namespace Lucinda\WebSecurity\Security\MultiFactorAuthentication;

use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication as Configuration;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication\Totp as TotpConfiguration;
use Lucinda\WebSecurity\DAO\MultiFactorAuthentication as MultiFactorAuthenticationDAO;
use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp\GoogleAuthenticator;

/**
 * Encapsulates Totp logic.
 */
final class Totp extends Generic
{
    private Configuration $configuration;
    private TotpConfiguration $method;
    private MultiFactorAuthenticationDAO $dao;
    private GoogleAuthenticator $googleAuthenticator;

    /**
     * Sets up object state.
     *
     * @param Configuration $configuration
     * @param Request $request
     * @param int|string $userID
     */
    public function __construct(Configuration $configuration, Request $request, int|string $userID)
    {
        $this->configuration = $configuration;
        $this->method = $configuration->getMethod();
        $this->request = $this->normalizeRequest($request, $this->method);
        $this->userID = $userID;
        $this->googleAuthenticator = new GoogleAuthenticator();

        $daoClass = $configuration->getDAO();
        $this->dao = new $daoClass();
        $this->outcome = $this->execute();
    }

    /**
     * Normalize request.
     *
     * @param Request $request
     * @param TotpConfiguration $configuration
     * @return Request
     */
    private function normalizeRequest(Request $request, TotpConfiguration $configuration): Request
    {
        $codeParameter = $configuration->getCodeParameter();
        if ($codeParameter === TotpConfiguration::DEFAULT_CODE_PARAMETER) {
            return $request;
        }

        $parameters = $request->getParameters();
        if (!isset($parameters[$codeParameter])) {
            return $request;
        }

        $request = clone $request;
        $parameters[TotpConfiguration::DEFAULT_CODE_PARAMETER] = $parameters[$codeParameter];
        $request->setParameters($parameters);
        return $request;
    }

    /**
     * Executes the configured security workflow.
     *
     * @return MultiFactorPacket|null
     */
    private function execute(): MultiFactorPacket|null
    {
        if (!$this->dao->isRequired($this->userID)) {
            return $this->compose(ResultStatus::NOT_REQUIRED, $this->configuration->getSuccessRoute());
        }

        if ($this->dao->isThrottled($this->userID)) {
            return $this->compose(ResultStatus::THROTTLED, $this->configuration->getThrottledRoute());
        }

        if ($this->request->getUri() === $this->configuration->getSetupRoute()) {
            return $this->setup();
        }

        if ($this->request->getUri() === $this->configuration->getChallengeRoute()) {
            return $this->challenge();
        }

        if ($this->dao->getSecret($this->userID) === null) {
            return $this->setupRequired();
        }

        return $this->compose(ResultStatus::REQUIRED, $this->configuration->getChallengeRoute());
    }

    /**
     * Sets up.
     *
     * @return MultiFactorPacket
     */
    private function setup(): MultiFactorPacket
    {
        $secret = $this->dao->getSetupSecret($this->userID);
        if ($secret === null) {
            $secret = $this->googleAuthenticator->generateSecret();
            $this->dao->saveSetupSecret($this->userID, $secret);
        }

        $code = $this->getCode();
        if ($code === null) {
            return $this->setupRequired($secret);
        }

        if ($this->googleAuthenticator->verify($secret, $code, $this->method->getPeriod(), $this->method->getDigits(), $this->method->getWindow())) {
            $this->dao->enable($this->userID, $secret);
            $this->dao->clearSetupSecret($this->userID);
            return $this->compose(ResultStatus::SUCCEEDED, $this->configuration->getSuccessRoute());
        }

        $this->dao->penalize($this->userID);
        return $this->compose(ResultStatus::FAILED, $this->configuration->getFailureRoute());
    }

    /**
     * Challenge.
     *
     * @return MultiFactorPacket
     */
    private function challenge(): MultiFactorPacket
    {
        $secret = $this->dao->getSecret($this->userID);
        if ($secret === null) {
            return $this->setupRequired();
        }

        $code = $this->getCode();
        if ($code === null) {
            return $this->compose(ResultStatus::REQUIRED, $this->configuration->getChallengeRoute());
        }

        if ($this->googleAuthenticator->verify($secret, $code, $this->method->getPeriod(), $this->method->getDigits(), $this->method->getWindow())) {
            return $this->compose(ResultStatus::SUCCEEDED, $this->configuration->getSuccessRoute());
        }

        $this->dao->penalize($this->userID);
        return $this->compose(ResultStatus::FAILED, $this->configuration->getFailureRoute());
    }

    /**
     * Sets up required.
     *
     * @param ?string $secret
     * @return MultiFactorPacket
     */
    private function setupRequired(?string $secret = null): MultiFactorPacket
    {
        if ($secret === null) {
            $secret = $this->dao->getSetupSecret($this->userID);
            if ($secret === null) {
                $secret = $this->googleAuthenticator->generateSecret();
                $this->dao->saveSetupSecret($this->userID, $secret);
            }
        }

        $packet = $this->compose(ResultStatus::SETUP_REQUIRED, $this->configuration->getSetupRoute());
        $packet->setSecret($secret);
        $packet->setProvisioningURI(
            $this->googleAuthenticator->getProvisioningURI(
                $this->method->getIssuer(),
                $this->dao->getAccountName($this->userID),
                $secret,
                $this->method->getPeriod(),
                $this->method->getDigits()
            )
        );
        return $packet;
    }

    /**
     * Gets code.
     *
     * @return ?string
     */
    private function getCode(): ?string
    {
        $parameters = $this->request->getParameters();
        $code = $parameters[TotpConfiguration::DEFAULT_CODE_PARAMETER] ?? null;
        if ($code === null || $code === "") {
            return null;
        }
        return (string) $code;
    }
}
