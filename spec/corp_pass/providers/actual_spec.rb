require 'timecop'

RSpec.describe CorpPass::Providers::Actual do
  let(:sp_entity) { 'https://sp.example.com/saml/metadata' }
  let(:idp_entity) { 'https://idp.example.com/saml2/idp/metadata' }
  let(:idp_host) { URI.parse(idp_entity).host }

  subject { described_class.new }

  describe 'Entity Metadata' do
    it { expect(subject.send(:sp).entity_id).to eq(sp_entity) }
    it { expect(subject.send(:idp).entity_id).to eq(idp_entity) }
    # Disabled until CorpPass gives us a finalised URL
    it { expect(subject.send(:sso_url)).to eq(CorpPass.configuration.sso_idp_initiated_base_url) }
    it do
      expect(subject.send(:artifact_resolution_url))
        .to eq('https://idp.example.com/saml2/idp/ArtifactResolutionService')
    end
    it do
      expect(subject.send(:slo_url_redirect))
        .to eq('https://idp.example.com/saml2/idp/SingleLogoutService')
    end
    it do
      expect(subject.send(:slo_url_soap))
        .to eq('https://idp.example.com/saml2/idp/SingleLogoutService')
    end
  end

  describe 'SSO' do
    context 'IDP Initiated SSO HTTP-Redirect' do
      it 'returns a correctly formatted SSO URL' do
        expected_params = []
        expected_params << %w(RequestBinding HTTPArtifact)
        expected_params << %w(ResponseBinding HTTPArtifact)
        expected_params << ['PartnerId', sp_entity]
        expected_params << %w(Target https://sp.example.com)
        expected_params << %w(NameIdFormat Email)
        expected_params << %w(esrvcID Foobar)
        # expected_params << %w(param1 NULL)
        # expected_params << %w(param2 NULL)
        actual_url = subject.sso_idp_initiated_url
        actual_uri = URI(actual_url)
        actual_params = URI.decode_www_form(actual_uri.query.nil? ? '' : actual_uri.query)
        expect(actual_params).to match_array(expected_params)
      end
    end
  end

  describe 'SLO' do
    before(:all) do
      sp = 'https://sp.example.com/saml/metadata'
      Saml.current_provider = Saml.provider(sp)
      CorpPass.configuration.sp_entity = sp
    end

    after(:all) do
      CorpPass::Test::Config.reset_configuration!
    end

    context 'HTTP-Redirect' do
      it 'creates the right SP initiated request' do
        _, slo_request = subject.slo_request_redirect('S1234567A')
        expect(slo_request.name_id).to eq('S1234567A')
        expect(slo_request.issuer).to eq(sp_entity)
      end

      it 'creates the right IDP Initiated response' do
        destination = Saml.provider(sp_entity).single_logout_service_url(Saml::ProtocolBinding::HTTP_REDIRECT)
        request = Saml::LogoutRequest.new(name_id: 'S1234567A',
                                          destination: destination,
                                          issuer: idp_entity)
        _, slo_response = subject.slo_response_redirect request
        expect(slo_response.in_response_to).to eq(request._id)
      end
    end
  end

  describe CorpPass::Providers::ActualStrategy do
    before(:all) do
      sp = 'https://sp.example.com/saml/metadata'
      Saml.current_provider = Saml.provider(sp)
      CorpPass.configuration.sp_entity = sp
      Timecop.freeze(Time.utc(2015, 11, 30, 4, 45))
    end

    after(:all) do
      Timecop.return
      CorpPass::Test::Config.reset_configuration!
    end

    subject { CorpPass::Providers::ActualStrategy.new(nil) }

    let(:request) do
      req = double(:request)
      allow(req).to receive(:params).and_return('SAMLArt': 'foobar')
      req
    end

    let(:artifact_resolution_url) do
      subject.send(:artifact_resolution_url)
    end

    describe :resolve_artifact! do
      let(:saml_response) { create(:saml_response, :encrypt_id, :encrypt_assertion) }
      let(:artifact_response) do
        artifact_response = Saml::ArtifactResponse.new(status_value: Saml::TopLevelCodes::SUCCESS)
        artifact_response.response = saml_response
        artifact_response
      end

      context 'Successful resolution' do
        it 'resolves the artifact' do
          expect(Saml::Bindings::HTTPArtifact).to(receive(:resolve)) { saml_response }
          response = nil
          expect { response = subject.resolve_artifact!(double(:request)) }.to_not throw_symbol(:warden)
          expect(response).to_not be nil
          expect(response.class).to eq(CorpPass::Response)
        end
      end

      context 'Network error' do
        it 'retries after a first network error' do
          expect(Saml::Util).to(receive(:verify_xml)) { artifact_response }
          stub_request(:any, artifact_resolution_url).to_timeout.times(1)
                                                     .then.to_return(body: artifact_response.to_soap)
          expect(subject).to receive(:resolve_artifact!).twice.and_call_original
          expect { subject.resolve_artifact!(request) }.to_not throw_symbol
        end

        it 'throws with the right details when it timesout twice' do
          stub_request(:any, artifact_resolution_url).to_timeout.times(2)
          expect(subject).to receive(:resolve_artifact!).twice.and_call_original
          expect { subject.resolve_artifact!(request) }
            .to throw_symbol(:warden, scope: CorpPass::WARDEN_SCOPE,
                                      exception: instance_of(Timeout::Error),
                                      type: :exception)
        end
      end

      context 'Saml error' do
        it 'throws with the right details' do
          expect(Saml::Bindings::HTTPArtifact).to receive(:resolve) do |_, _|
            Saml::ArtifactResponse.parse('<badxml>')
          end
          expect { subject.resolve_artifact!(double(:request)) }
            .to throw_symbol(:warden, scope: CorpPass::WARDEN_SCOPE,
                                      type: :exception,
                                      exception: instance_of(Saml::Errors::UnparseableMessage))
        end
      end

      context 'ArtifactResolutionFailure' do
        let(:exception) { CorpPass::Providers::ArtifactResolutionFailure.new('Artifact resolution failed', nil) }
        it 'throws with the right details' do
          expect(Saml::Bindings::HTTPArtifact).to receive(:resolve) do |_, _|
            raise exception # rubocop:disable Style/SignalException)
          end
          expect { subject.resolve_artifact!(double(:request)) }
            .to throw_symbol(:warden, scope: CorpPass::WARDEN_SCOPE,
                                      exception: exception,
                                      type: :exception)
        end
      end

      context 'MissingAssertionError' do
        it 'throws :warden if the SAML response has no assertions' do
          expect(Saml::Bindings::HTTPArtifact).to receive(:resolve) do |_, _|
            create(:saml_response, :no_assertion)
          end
          expect { subject.resolve_artifact!(double(:request)) }
            .to throw_symbol(:warden,
                             scope: CorpPass::WARDEN_SCOPE, type: :exception,
                             exception: instance_of(CorpPass::MissingAssertionError))
        end
      end
    end

    describe :check_response! do
      it 'raises an exception when the status is not success' do
        response = Saml::Response.new(sub_status_value: Saml::SubStatusCodes::AUTHN_FAILED)
        expect { subject.check_response!(response) }.to raise_error(CorpPass::Providers::ArtifactResolutionFailure)
      end

      it 'raises an exception when the SAML Response received is invalid' do
        response = create(:saml_response, :invalid)
        expect(response).to receive(:success?).twice.and_return(true) # Skip the ArtifactResolutionFailure exception
        expect { subject.check_response!(response) }
          .to throw_symbol(:warden, scope: CorpPass::WARDEN_SCOPE,
                                    exception: instance_of(CorpPass::Providers::SamlResponseValidationFailure),
                                    type: :exception)
      end
    end

    describe :authenticate! do
      let(:response) do
        saml_response = create(:saml_response, :encrypt_id, :encrypt_assertion)
        CorpPass::Response.new(saml_response)
      end

      before(:each) do
        expect(subject).to receive(:resolve_artifact!).and_return(response)
      end

      it 'successfully authenticates given the right response' do
        expect(subject).to receive(:success!)
        subject.authenticate!
      end

      it 'throws :warden if the user provided fails validation' do
        expect(response.cp_user).to receive(:validate!) do
          raise CorpPass::InvalidUser.new('', nil) # rubocop:disable Style/SignalException)
        end
        expect { subject.authenticate! }
          .to throw_symbol(:warden,
                           scope: CorpPass::WARDEN_SCOPE, type: :exception,
                           exception: instance_of(CorpPass::InvalidUser))
      end
    end
  end

  describe 'Authentication with Warden' do
    include CorpPass::Test::RackHelper

    before(:all) do
      @sp_entity = 'https://sp.example.com/saml/metadata'
      @sp = Saml.provider(@sp_entity)
      @idp_entity = 'https://idp.example.com/saml2/idp/metadata'
      @idp = Saml.provider(@idp_entity)
      Saml.current_provider = @sp
      CorpPass.configuration.sp_entity = @sp_entity
      Timecop.freeze(Time.utc(2015, 11, 30, 4, 45))

      @mapping = {
        '/' => proc do
          run CorpPass::Test::RackHelper::SUCCESS_APP
        end,
        '/sso' => proc do
                    app = lambda do |env|
                      response = Rack::Response.new
                      location = '/'
                      location = CorpPass.sso_idp_initiated_url unless CorpPass.authenticated?(env['warden'])
                      response.redirect(location)
                      response
                    end
                    run app
                  end,
        '/acs' => proc do
                    app = lambda do |env|
                      CorpPass.authenticate!(env['warden'])
                      CorpPass::Test::RackHelper::SUCCESS_RESPONSE
                    end
                    run app
                  end,
        '/slo' => proc do
                    app = lambda do |env|
                      request = Rack::Request.new(env)
                      if request[:SAMLRequest] # IdP initiated SLO
                        logout_request = CorpPass.parse_logout_request request
                        if logout_request.name_id == env['warden'].user.info.id
                          CorpPass.logout(env['warden'])
                          slo_url, _logout_response = CorpPass.slo_response_redirect(logout_request)
                          response = Rack::Response.new
                          response.redirect(slo_url)
                          response
                        else
                          CorpPass::Test::RackHelper::FAILURE_RESPONSE
                        end
                      elsif request[:SAMLResponse] # SP initiated SLO response from IdP
                        logout_response = CorpPass.parse_logout_response(request)
                        if logout_response.in_response_to == env['rack.session']['logout_id'] &&
                           logout_response.success?
                          CorpPass.logout(env['warden'])
                          CorpPass::Test::RackHelper::SUCCESS_RESPONSE
                        else
                          CorpPass::Test::RackHelper::FAILURE_RESPONSE
                        end
                      else # Start SP initiated SLO
                        url, logout_request = CorpPass.slo_request_redirect(env['warden'].user.info.id)
                        env['rack.session']['logout_id'] = logout_request._id
                        response = Rack::Response.new
                        response.redirect(url)
                        response
                      end
                    end
                    run app
                  end
      }
      @app = setup_rack(nil, @mapping).to_app
    end

    after(:each) do
      Warden.test_reset!
    end

    after(:all) do
      Timecop.return
      CorpPass::Test::Config.reset_configuration!
    end

    it 'authenticates successfully' do
      env = env_with_params('/sso')
      response = @app.call(env)
      expect(response[0]).to eq 302
      expect(response[1]).to include('Location' => CorpPass.sso_idp_initiated_url)

      saml_response = create(:saml_response, :encrypt_id, :encrypt_assertion)
      acs = @sp.assertion_consumer_service
      artifact_response = Saml::ArtifactResponse.new(status_value: Saml::TopLevelCodes::SUCCESS,
                                                     issuer: idp_entity,
                                                     destination: acs)
      artifact_response.response = saml_response

      artifact_resolution_url = Saml.provider(idp_entity).artifact_resolution_service_url(0)
      stub_request(:post, artifact_resolution_url).to_return(body: Saml::Util.sign_xml(artifact_response, :soap))
      env = env_with_params('/acs', { 'SAMLart' => 'foobar' }, env)
      response = @app.call(env)
      expect(response[0]).to eq(200)
      expect(CorpPass.authenticated?(env['warden'])).to be true
    end

    it 'calls the failure app when authentication fails' do
      artifact_resolution_url = Saml.provider(idp_entity).artifact_resolution_service_url(0)
      stub_request(:post, artifact_resolution_url).to_timeout.times(2)
      env = env_with_params('/acs', 'SAMLart' => 'foobar')
      response = @app.call(env)
      expect(response).to eq CorpPass::Test::RackHelper::FAILURE_RESPONSE
      expect(CorpPass.authenticated?(env['warden'])).to be false
    end

    it 'performs a SP initiated SLO properly' do
      user = create :corp_pass_user
      login_as(user)
      env = env_with_params('/slo')
      response = @app.call(env)
      expect(env['warden'].authenticated?).to be true

      Saml.current_provider = @idp
      idp_env = env_with_url(response[2].location)
      logout_request = nil
      expect do
        logout_request = Saml::Bindings::HTTPRedirect.receive_message(Rack::Request.new(idp_env), type: :logout_request)
      end.to_not raise_error

      # Make LogoutResponse
      Saml.current_provider = @sp
      destination = @sp.single_logout_service_url(Saml::ProtocolBinding::HTTP_REDIRECT)
      logout_response = Saml::LogoutResponse.new destination: destination,
                                                 in_response_to: logout_request._id,
                                                 issuer: @idp_entity,
                                                 status_value: Saml::TopLevelCodes::SUCCESS
      response_url = ::URI.parse(Saml::Bindings::HTTPRedirect.create_url(logout_response))
      env = env_with_params('/slo', CGI.parse(response_url.query), env)
      response = @app.call(env)
      expect(response[0]).to eq(200)
      expect(env['warden'].authenticated?).to be false
    end

    it 'performs an IdP initiated SLO properly' do
      user = create :corp_pass_user
      login_as(user)

      destination = @sp.single_logout_service_url(Saml::ProtocolBinding::HTTP_REDIRECT)
      logout_request = Saml::LogoutRequest.new destination: destination,
                                               name_id: user.info.id,
                                               issuer: @idp_entity
      request_url = ::URI.parse(Saml::Bindings::HTTPRedirect.create_url(logout_request))
      env = env_with_params('/slo', CGI.parse(request_url.query))
      response = @app.call(env)

      expect(response[0]).to eq 302
      Saml.current_provider = @idp
      idp_env = env_with_url(response[2].location)
      expect do
        Saml::Bindings::HTTPRedirect.receive_message(Rack::Request.new(idp_env), type: :logout_response)
      end.to_not raise_error
      expect(env['warden'].authenticated?).to be false
      Saml.current_provider = @sp
    end
  end
end
