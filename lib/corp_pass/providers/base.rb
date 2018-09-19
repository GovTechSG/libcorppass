require 'saml'
require 'corp_pass/timeout'
require 'corp_pass/notification'

module CorpPass
  module Providers
    # @abstract
    class Base
      include CorpPass::Notification

      def initialize; end

      # Override to perform any kinds of setup required
      # @abstract
      def setup; end

      # Returns a URL to redirect to for IdP initiated SSO
      # @abstract
      def sso_idp_initiated_url
        fail NotImplementedError, 'Method not implemented'
      end

      # Builds a SAML +<LogoutRequest>+ and a redirect URL to initiate an SP-initiated SLO.
      # @abstract
      def slo_request_redirect(name_id) # rubocop:disable Lint/UnusedMethodArgument
        fail NotImplementedError, 'Method not implemented'
      end

      # Builds a SAML +<LogoutResponse>+ and a redirect URL in response to an IdP-initiated SLO.
      # @abstract
      def slo_response_redirect(logout_request) # rubocop:disable Lint/UnusedMethodArgument
        fail NotImplementedError, 'Method not implemented'
      end

      # Parse a SAML +<LogoutResponse>+ received via a HTTP Request in response to an SP-initiated SLO.
      # @param request [Rack::Request] a +Rack::Request+
      #   (or similarly behaved, like +ActionDispatch::Request+ from Rails)
      # @return [Saml::Elements::LogoutResponse]
      def parse_logout_response(request)
        message = Saml::Bindings::HTTPRedirect.receive_message(request, type: :logout_response)
        notify(CorpPass::Events::SLO_RESPONSE, message.to_xml)
        message
      end

      # Parse a SAML +<LogoutRequest>+ received via a HTTP Request in response to an IdP-initiated SLO.
      # @param request [Rack::Request] a +Rack::Request+
      #   (or similarly behaved, like +ActionDispatch::Request+ from Rails)
      # @return [Saml::Elements::LogoutRequest]
      def parse_logout_request(request)
        message = Saml::Bindings::HTTPRedirect.receive_message(request, type: :logout_request)
        notify(CorpPass::Events::SLO_REQUEST, message.to_xml)
        message
      end

      # Performs a Warden logout
      def logout(warden)
        warden.logout(CorpPass::WARDEN_SCOPE)
      end

      # Returns the Warden strategy name associated with this provider
      # @abstract
      def warden_strategy_name
        fail NotImplementedError, 'Method not implemented'
      end

      # Returns the Warden strategy class associated with this provider
      # @abstract
      def warden_strategy
        fail NotImplementedError, 'Method not implemented'
      end

      private

      def configuration
        CorpPass.configuration
      end

      def sp
        @sp ||= Saml.provider(configuration.sp_entity)
      end

      def idp
        @idp ||= Saml.provider(configuration.idp_entity)
      end
    end

    # Abstract strategy. Refer to Warden::Strategy documentation.
    # @abstract
    class BaseStrategy < Warden::Strategies::Base
      def warden
        env['warden']
      end

      def valid?
        self.class == CorpPass.provider.warden_strategy
      end

      def configuration
        CorpPass.configuration
      end
    end
  end
end
