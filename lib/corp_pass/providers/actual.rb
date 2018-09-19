require 'saml'
require 'corp_pass/providers/base'
require 'corp_pass/response'

module CorpPass
  module Providers
    # A concrete implementation of an actual CorpPass provider.
    #
    # See: {ActualStrategy}
    class Actual < Base
      # @return [String] the URL to redirect to for IdP-initiated SSO.
      def sso_idp_initiated_url
        uri = URI(sso_url)
        params = sso_idp_initiated_url_params(uri)
        uri.query = URI.encode_www_form(params)
        notify(CorpPass::Events::SSO_IDP_INITIATED_URL, uri.to_s)
      end

      # Build a SAML +<LogoutRequest>+ and a redirect URL to initiate a SP-initiated SLO.
      # @param name_id [String] the +name_id+ being logged out (ie. the +NameID+ from +<Subject>+ in the SAML assertion)
      # @return [Array<String, Saml::Elements::LogoutRequest>] an array +[url, logout_request]+ where
      #                                                        +url+ is the URL to redirect to
      def slo_request_redirect(name_id)
        slo_request = make_sp_initiated_slo_request name_id, binding: :redirect
        [Saml::Bindings::HTTPRedirect.create_url(slo_request), slo_request]
      end

      # Build a SAML +<LogoutResponse>+ and a redirect URL in response to an IdP-initiated SLO.
      #
      # @param logout_request [Saml::Elements::LogoutRequest] received from the IdP
      # @return [Array<String, Saml::Elements::LogoutResponse>] an array +[url, logout_response]+ where
      #                                                         +url+ is the URL to redirect to
      def slo_response_redirect(logout_request)
        slo_response = make_idp_initiated_slo_response logout_request, binding: :redirect
        [Saml::Bindings::HTTPRedirect.create_url(slo_response), slo_response]
      end

      # @return [String]
      def artifact_resolution_url
        idp.artifact_resolution_service_url(configuration.artifact_resolution_service_url_index)
      end

      # @return [Symbol] the symbol of the strategy used by this provider.
      def warden_strategy_name
        :corp_pass_actual
      end

      # @return [Class] the class of the strategy used by this provider.
      def warden_strategy
        CorpPass::Providers::ActualStrategy
      end

      private

      def sso_idp_initiated_url_params(uri)
        params = URI.decode_www_form(uri.query.nil? ? '' : uri.query)
        params.concat([
                        %w(RequestBinding HTTPArtifact),
                        %w(ResponseBinding HTTPArtifact),
                        ['PartnerId', configuration.sp_entity],
                        ['Target', configuration.sso_target],
                        %w(NameIdFormat Email),
                        ['esrvcID', configuration.eservice_id]
                      ])
        # params << %w(param1 NULL)
        # params << %w(param2 NULL)
        params
      end

      # Binding can be :redirect or :soap
      def make_sp_initiated_slo_request(name_id, binding: :redirect)
        destination = binding == :redirect ? slo_url_redirect : slo_url_soap
        slo_request = Saml::LogoutRequest.new destination: destination,
                                              name_id: name_id
        notify(CorpPass::Events::SLO_REQUEST, slo_request.to_xml)
        slo_request
      end

      def make_idp_initiated_slo_response(logout_request, binding: :redirect)
        destination = binding == :redirect ? slo_url_redirect : slo_url_soap
        slo_response = Saml::LogoutResponse.new destination: destination,
                                                in_response_to: logout_request._id,
                                                status_value: Saml::TopLevelCodes::SUCCESS
        notify(CorpPass::Events::SLO_RESPONSE, slo_response.to_xml)
        slo_response
      end

      def sso_url
        configuration.sso_idp_initiated_base_url
      end

      def slo_url_redirect
        idp.single_logout_service_url(Saml::ProtocolBinding::HTTP_REDIRECT)
      end

      def slo_url_soap
        idp.single_logout_service_url(Saml::ProtocolBinding::SOAP)
      end
    end

    class ArtifactResolutionFailure < CorpPass::Error
      attr_reader :response
      def initialize(message, response)
        super(message)
        @response = response
      end
    end

    class SamlResponseValidationFailure < CorpPass::Error
      attr_reader :xml
      attr_reader :messages
      def initialize(messages, xml)
        super(messages.join('; '))
        @messages = messages
        @xml = xml
      end
    end

    # A concrete implementation of {CorpPass::Providers::BaseStrategy} for the actual CorpPass provider.
    #
    # See: {CorpPass::Providers::BaseStrategy}, {Actual}
    class ActualStrategy < BaseStrategy
      include CorpPass::Notification

      # @return [String]
      def artifact_resolution_url
        CorpPass.provider.artifact_resolution_url
      end

      def valid?
        notify(CorpPass::Events::STRATEGY_VALID,
               super && !warden.authenticated?(CorpPass::WARDEN_SCOPE) && !params['SAMLart'].blank?)
      end

      # Authenticates the user against the artifact received in the SAML response.
      def authenticate!
        response = resolve_artifact!(request)
        user = response.cp_user
        notify(CorpPass::Events::AUTH_ACCESS, user.xml)
        begin
          user.validate!
        rescue CorpPass::InvalidUser => e
          notify(CorpPass::Events::INVALID_USER, "User XML validation failed: #{e}\nXML Received was:\n#{e.xml}")
          CorpPass::Util.throw_exception(e, CorpPass::WARDEN_SCOPE)
        end
        notify(CorpPass::Events::LOGIN_SUCCESS, "Logged in successfully #{user.info.id} -- 2FA: #{user.twofa?}")
        success! user
      end

      # List of network exceptions. Artifact resolution is retried when one of these exceptions is
      # caught in {#resolve_artifact!}.
      NETWORK_EXCEPTIONS = [::Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError,
                            Net::HTTPBadResponse, Net::HTTPHeaderSyntaxError, Net::ProtocolError].freeze

      # Rubocop: This method is concerned with rescuing from various exceptions so AbcSize is disabled
      #
      # @param request [Rack::Request] A +Rack::Request+-like object
      # @param retrying_attempt [Boolean] whether the resolution is a retry attempt. +resolve_artifact!+ will only
      #                                   retry at most once.
      def resolve_artifact!(request, retrying_attempt = false) # rubocop:disable Metrics/AbcSize
        saml_response = Saml::Bindings::HTTPArtifact.resolve(request, artifact_resolution_url, {}, proxy)
        check_response!(saml_response)
      rescue *NETWORK_EXCEPTIONS => e
        if retrying_attempt
          notify(CorpPass::Events::NETWORK_ERROR, "Network error resolving artifact: #{e}")
          CorpPass::Util.throw_exception(e, CorpPass::WARDEN_SCOPE)
        else
          notify(CorpPass::Events::RETRY_AUTHENTICATION, "Retrying authentication due to #{e}")
          return resolve_artifact!(request, true)
        end
      rescue Saml::Errors::SamlError => e
        notify(CorpPass::Events::SAML_ERROR, "Saml Error: #{e.class.name} - #{e}")
        CorpPass::Util.throw_exception(e, CorpPass::WARDEN_SCOPE)
      rescue ArtifactResolutionFailure => e
        notify(CorpPass::Events::ARTIFACT_RESOLUTION_FAILURE,
               "Artifact resolution failure: #{e.response.try(:to_xml) || e.response.to_s}")
        CorpPass::Util.throw_exception(e, CorpPass::WARDEN_SCOPE)
      rescue CorpPass::MissingAssertionError => e
        notify(CorpPass::Events::MISSING_ASSERTION, "SAML response is missing assertion: #{e}")
        CorpPass::Util.throw_exception(e, CorpPass::WARDEN_SCOPE)
      end

      # Checks whether the SAML artifact response received from IdP is valid and has a successful status code.
      # Also validates that the response is compliant with the CorpPass specification.
      # @return [Response] SAML response received from the IdP.
      def check_response!(response)
        unless response.try(:success?)
          raise ArtifactResolutionFailure.new('Artifact resolution failed', # rubocop:disable Style/SignalException
                                              response)
        end
        response_xml = notify(CorpPass::Events::SAML_RESPONSE, response.to_xml)
        cp_response = CorpPass::Response.new(response)
        unless cp_response.valid?
          notify(CorpPass::Events::SAML_RESPONSE_VALIDATION_FAILURE,
                 "SamlResponse Validation failed failure: #{cp_response.errors} \n#{response_xml}")
          exception = SamlResponseValidationFailure.new(cp_response.errors, response_xml)
          CorpPass::Util.throw_exception(exception, CorpPass::WARDEN_SCOPE)
        end
        cp_response
      end

      # Returns the proxy configuration for this strategy.
      # @return [Hash] A Hash with the keys +:addr+ and +:port+.
      def proxy
        return {} if configuration.proxy_address.blank?
        {
          addr: configuration.proxy_address,
          port: configuration.proxy_port ? configuration.proxy_port.to_i : nil
        }
      end
    end
  end
end
