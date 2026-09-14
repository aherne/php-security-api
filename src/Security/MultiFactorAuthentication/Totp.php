<?php

namespace Lucinda\WebSecurity\Security\MultiFactorAuthentication;

use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication as Configuration;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication\Totp as TotpConfiguration;
use Lucinda\WebSecurity\DAO\MultiFactorAuthentication as MultiFactorAuthenticationDAO;
use Lucinda\WebSecurity\DAO\Throttler\MultiFactorAuthentication as MultiFactorAuthenticationThrottler;
use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;
use Lucinda\WebSecurity\Packets\Throttling;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp\GoogleAuthenticator;

/**
 * Executes TOTP enrollment or verification and produces an MFA outcome
 *
 * Coordinates MFA policy, throttling, enrollment storage, code verification,
 * and one-time counter consumption through the configured DAOs. Enrollment
 * is selected only when no enrolled secret exists.
 *
 * Construction executes the workflow and may modify enrollment data,
 * consume a verified counter, or record a failed attempt. The resulting
 * packet is available through getOutcome(); authentication persistence
 * remains the enclosing wrapper's responsibility.
 *
 * @see \Lucinda\WebSecurity\Configuration\MultiFactorAuthentication
 * @see \Lucinda\WebSecurity\DAO\MultiFactorAuthentication
 * @see \Lucinda\WebSecurity\DAO\Throttler\MultiFactorAuthentication
 * @see \Lucinda\WebSecurity\Packets\MultiFactor
 */
final class Totp extends Generic
{
    private Configuration $configuration;
    private TotpConfiguration $method;
    private MultiFactorAuthenticationDAO $dao;
    private MultiFactorAuthenticationThrottler $throttler;
    private GoogleAuthenticator $googleAuthenticator;

    /**
     * Constructs the TOTP collaborators and executes enrollment or verification
     *
     * @param Configuration $configuration Parsed MFA settings, TOTP options, and DAO classes
     * @param Request $request Current request supplying the route, HTTP method, code, and client IP
     * @param int|string $userID Non-empty local ID whose MFA requirements are evaluated
     * @throws \Throwable If DAO initialization, throttling, randomness, or TOTP processing fails
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

        $throttlerClass = $configuration->getThrottler();
        $this->throttler = new $throttlerClass();

        $this->outcome = $this->execute();
    }

    /**
     * Maps the configured code parameter to the canonical TOTP parameter name
     *
     * Clones the request only when a non-default submitted parameter is present.
     * The original request is not modified, and the code value is not validated here.
     *
     * @param Request $request Original request carrying submitted parameters
     * @param TotpConfiguration $configuration TOTP settings specifying the submitted code parameter
     * @return Request Original request when no mapping is needed, otherwise a clone with the canonical parameter
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
     * Selects the MFA policy, enrollment, or challenge outcome
     *
     * Checks whether MFA is required before checking throttling. Enrollment is
     * selected when no factor is enrolled; enrolled users proceed to challenge
     * handling or receive a callback to the challenge route.
     *
     * @return MultiFactorPacket|Throttling|null Selected MFA outcome
     * @throws \Throwable If a DAO, throttler, or TOTP operation fails
     */
    private function execute(): MultiFactorPacket|Throttling|null
    {
        if (!$this->dao->isRequired($this->userID)) {
            return $this->compose(ResultStatus::NOT_REQUIRED, $this->configuration->getSuccessRoute());
        }

        if ($this->throttler->isThrottled($this->userID, $this->request->getIpAddress())) {
            return $this->composeThrottling($this->configuration->getThrottledRoute());
        }

        $enrolledSecret = $this->dao->getSecret($this->userID);

        if ($enrolledSecret === null) {
            if ($this->request->getUri() === $this->configuration->getSetupRoute()) {
                return $this->setup();
            }

            return $this->setupRequired();
        }

        if ($this->request->getUri() === $this->configuration->getChallengeRoute()) {
            return $this->challenge();
        }

        return $this->compose(ResultStatus::REQUIRED, $this->configuration->getChallengeRoute());
    }

    /**
     * Confirms TOTP enrollment using a temporary setup secret
     *
     * Called after the workflow found no enrolled secret. Reuses or creates a
     * temporary secret. A verified, successfully consumed code enables the
     * factor and clears the temporary secret; a missing code returns setup data.
     *
     * @return MultiFactorPacket|Throttling Setup data, successful enrollment, or a failed/throttled attempt
     * @throws \Throwable If temporary-secret storage, verification, enrollment, or throttling fails
     */
    private function setup(): MultiFactorPacket|Throttling
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

        if ($this->verifyAndConsume($secret, $code)) {
            $this->dao->enable($this->userID, $secret);
            $this->dao->clearSetupSecret($this->userID);
            return $this->compose(ResultStatus::SUCCEEDED, $this->configuration->getSuccessRoute());
        }
        
        return $this->fail();
    }

    /**
     * Verifies a submitted code against the enrolled TOTP secret
     *
     * A missing code returns the challenge requirement. If no enrolled secret
     * is available, returns setup data instead. Failed verification or counter
     * consumption records a failed attempt.
     *
     * @return MultiFactorPacket|Throttling Challenge requirement, setup data, success, or a failed/throttled attempt
     * @throws \Throwable If a DAO, throttler, or TOTP operation fails
     */
    private function challenge(): MultiFactorPacket|Throttling
    {
        $secret = $this->dao->getSecret($this->userID);
        if ($secret === null) {
            return $this->setupRequired();
        }

        $code = $this->getCode();
        if ($code === null) {
            return $this->compose(ResultStatus::REQUIRED, $this->configuration->getChallengeRoute());
        }

        if ($this->verifyAndConsume($secret, $code)) {
            return $this->compose(ResultStatus::SUCCEEDED, $this->configuration->getSuccessRoute());
        }

        return $this->fail();
    }

    /**
     * Builds the enrollment outcome with a temporary secret and provisioning URI
     *
     * Reuses a supplied or stored setup secret, generating and storing one when
     * necessary. Does not enable the factor. The packet contains sensitive
     * enrollment material that must be excluded from logs.
     *
     * @param string|null $secret Base32-encoded setup secret, or null to load or generate one
     * @return MultiFactorPacket SETUP_REQUIRED packet carrying enrollment data and the setup callback
     * @throws \Throwable If setup-secret storage, account lookup, or random generation fails
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
     * Reads a submitted TOTP code from a POST request
     *
     * Accepts string or integer parameter values and converts integers to strings.
     * Code length and decimal format are checked later during verification.
     *
     * @return string|null Submitted non-empty code, or null for non-POST, missing, empty, or unsupported values
     */
    private function getCode(): ?string
    {
        if ($this->request->getMethod() !== "POST") {
            return null;
        }

        $parameters = $this->request->getParameters();
        $code = $parameters[TotpConfiguration::DEFAULT_CODE_PARAMETER] ?? null;

        if (!is_string($code) && !is_int($code)) {
            return null;
        }

        $code = (string) $code;

        return $code === "" ? null : $code;
    }

    /**
     * Verifies the submitted TOTP and consumes its matched counter through the DAO
     *
     * A matching code alone is insufficient: the DAO must atomically accept its
     * counter as unused. This also applies when confirming enrollment.
     *
     * @param string $secret Base32-encoded setup or enrolled secret
     * @param string $code Submitted decimal verification code
     * @return bool True only when the code matches and its counter is successfully consumed
     * @throws \Throwable If TOTP processing or counter consumption fails
     */
    private function verifyAndConsume(string $secret, string $code): bool
    {
        $counter = $this->googleAuthenticator->verify(
            $secret,
            $code,
            $this->method->getPeriod(),
            $this->method->getDigits(),
            $this->method->getWindow()
        );

        return $counter !== null && $this->dao->consumeTotpCounter($this->userID, $counter);
    }

    /**
     * Records a failed MFA attempt and composes its outcome
     *
     * Checks throttling again after recording the failure, so the same attempt
     * may produce a throttling outcome instead of an ordinary failure.
     *
     * @return MultiFactorPacket|Throttling FAILED or THROTTLED packet with its configured callback
     * @throws \Throwable If the throttler cannot record or evaluate the failed attempt
     */
    private function fail(): MultiFactorPacket|Throttling
    {
        $ipAddress = $this->request->getIpAddress();
        $this->throttler->penalize($this->userID, $ipAddress);
        if ($this->throttler->isThrottled($this->userID, $ipAddress)) {
            return $this->composeThrottling(
                $this->configuration->getThrottledRoute()
            );
        }
        return $this->compose(ResultStatus::FAILED, $this->configuration->getFailureRoute());
    }
}
