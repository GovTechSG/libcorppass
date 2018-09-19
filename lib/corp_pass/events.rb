module CorpPass
  # Events and log levels for {CorpPass::Logger}.
  #
  # See: {CorpPass::Logger}
  module Events
    PREFIX = /corp_pass\.(.+)/

    # Authentication
    INVALID_USER = 'invalid_user'.freeze
    LOGIN_SUCCESS = 'login_success'.freeze
    LOGIN_FAILURE = 'login_failure'.freeze
    NETWORK_ERROR = 'network_error'.freeze
    RETRY_AUTHENTICATION = 'retry_authentication'.freeze
    SAML_ERROR = 'saml_error'.freeze
    ARTIFACT_RESOLUTION_FAILURE = 'artifact_resolution_failure'.freeze
    SAML_RESPONSE_VALIDATION_FAILURE = 'saml_response_validation_failure'.freeze
    MISSING_ASSERTION = 'missing_assertion'.freeze

    # Provider
    SSO_IDP_INITIATED_URL = 'sso_idp_initiated_url'.freeze
    SLO_REQUEST = 'slo_request'.freeze
    SLO_RESPONSE = 'slo_response'.freeze
    SAML_RESPONSE = 'saml_response'.freeze
    STRATEGY_VALID = 'strategy_valid'.freeze
    AUTH_ACCESS = 'auth_access'.freeze

    # Response
    DECRYPTED_ASSERTION = 'decrypted_assertion'.freeze
    DECRYPTED_ID = 'decrypted_id'.freeze
    RESPONSE_VALIDATION_FAILURE = 'response_validation_failure'.freeze

    # User
    USER_VALIDATION_FAILURE = 'user_validation_failure'.freeze

    # Timeout
    SKIP_TIMEOUT_REFRESH = 'skip_timeout_refresh'.freeze
    INACTIVITY_TIMEOUT = 'inactivity_timeout'.freeze
    SESSION_TIMEOUT = 'session_timeout'.freeze

    LOG_LEVELS = {
      ::Logger::DEBUG => [SSO_IDP_INITIATED_URL, SLO_REQUEST, SLO_RESPONSE, SAML_RESPONSE,
                          STRATEGY_VALID, AUTH_ACCESS, DECRYPTED_ASSERTION, DECRYPTED_ID, SKIP_TIMEOUT_REFRESH],
      ::Logger::INFO => [LOGIN_SUCCESS, INACTIVITY_TIMEOUT, SESSION_TIMEOUT],
      ::Logger::WARN => [RETRY_AUTHENTICATION],
      ::Logger::ERROR => [INVALID_USER, LOGIN_FAILURE, NETWORK_ERROR, SAML_ERROR, ARTIFACT_RESOLUTION_FAILURE,
                          RESPONSE_VALIDATION_FAILURE, SAML_RESPONSE_VALIDATION_FAILURE, USER_VALIDATION_FAILURE,
                          MISSING_ASSERTION],
      ::Logger::FATAL => []
    }.freeze

    # {LOG_LEVELS} is sorted by key (log levels, which are integers) in a descending order,
    # converted back to a Hash, and then inverted so that the events become the keys.
    # Then, when we look up a log level, we can do one lookup with only the key (instead of using a (key, value) pair
    # to find the value when we need it, which is slower).
    LOG_LEVELS_INVERTED = LOG_LEVELS.sort.reverse!.to_h.invert.freeze

    # @param name [String]
    def self.extract_class(name)
      name.split('.')[1]
    end

    # @param name [String]
    def self.extract_event(name)
      name.split('.')[2..-1].join('.')
    end

    def self.find_log_level(event)
      key = LOG_LEVELS_INVERTED.keys.find do |events|
        events.include?(event)
      end
      key.nil? ? ::Logger::DEBUG : LOG_LEVELS_INVERTED[key]
    end
  end
end
