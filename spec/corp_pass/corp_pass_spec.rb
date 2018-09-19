RSpec.describe CorpPass do
  let(:yaml_file) { 'spec/fixtures/corp_pass/corp_pass.yml' }
  it { expect(CorpPass.configuration).to be_a(CorpPass::Config) }
  it { expect(CorpPass.provider).to be_a(CorpPass::Providers::Base) }

  # Note: There is only very little that we can test for configuration
  # We setup configuration in initializers/corp_pass and this sets up Warden
  # Since Warden is part of the Rack stack, it can only be set up once
  describe 'Configuration' do
    after(:all) do
      CorpPass::Test::Config.reset_configuration!
    end

    it { expect { |b| CorpPass.configure!(&b) }.to yield_with_args(CorpPass::Config) }

    it 'configure! creates a new configuration object after each configuration operation' do
      original = CorpPass.configuration
      CorpPass.configure! { |_config| }
      expect(CorpPass.configuration).to_not be original
    end

    it 'load_yaml! parses the .yml properly and loads the correct environment' do
      CorpPass.load_yaml!(yaml_file, 'test')
      expect(CorpPass.configuration.sp_entity).to eq('https://sp.example.com')
      expect(CorpPass.configuration.idp_entity).to eq('https://idp.example.com')
      expect(CorpPass.configuration.slo_enabled).to be true
    end

    it 'load_yaml! yields configuration when a block is provided' do
      expect { |b| CorpPass.load_yaml!(yaml_file, 'test', &b) }
        .to yield_with_args(CorpPass::Config)
    end

    it 'load_yaml! creates a new configuration object after each configuration operation' do
      original = CorpPass.configuration
      CorpPass.load_yaml!(yaml_file, 'test')
      expect(CorpPass.configuration).to_not be original
    end
  end

  it ':setup_provider creates a new provider each time' do
    original = CorpPass.provider
    CorpPass.setup_provider!
    expect(CorpPass.provider).to_not be original
  end

  describe 'Provider proxy methods' do
    before(:each) do
      @provider = double(:provider)
      expect(CorpPass).to receive(:provider).and_return(@provider)
    end

    it 'calls sso_idp_initiated_url on the provider' do
      expect(@provider).to receive(:sso_idp_initiated_url)
      CorpPass.sso_idp_initiated_url
    end

    it 'calls slo_request_redirect on the provider' do
      expect(@provider).to receive(:slo_request_redirect).with('foobar')
      CorpPass.slo_request_redirect('foobar')
    end

    it 'calls slo_response_redirect on the provider' do
      expect(@provider).to receive(:slo_response_redirect).with('foobar')
      CorpPass.slo_response_redirect('foobar')
    end

    it 'calls parse_logout_response on the provider' do
      expect(@provider).to receive(:parse_logout_response).with('foobar')
      CorpPass.parse_logout_response('foobar')
    end

    it 'calls parse_logout_request on the provider' do
      expect(@provider).to receive(:parse_logout_request).with('foobar')
      CorpPass.parse_logout_request('foobar')
    end

    it 'calls logout on the provider' do
      expect(@provider).to receive(:logout).with('foobar')
      CorpPass.logout('foobar')
    end
  end

  describe ':make_provider' do
    after(:all) do
      CorpPass::Test::Config.reset_configuration!
    end

    # Get eigenclass of object and then find included modules
    # Reference https://stackoverflow.com/questions/1328068
    def eigenclass(obj)
      (class << obj; self; end)
    end

    it 'does not include StubLogout when SLO is enabled' do
      CorpPass.configuration.slo_enabled = true
      actual_provider = CorpPass.send(:make_provider)
      expect(eigenclass(actual_provider).included_modules).to_not include(CorpPass::Providers::StubLogout)
    end

    it 'does include StubLogout when SLO is disabled' do
      CorpPass.configuration.slo_enabled = false
      actual_provider = CorpPass.send(:make_provider)
      expect(eigenclass(actual_provider).included_modules).to include(CorpPass::Providers::StubLogout)
    end
  end
  describe 'Session serialization' do
    include CorpPass::Test::RackHelper

    after(:each) do
      Warden.test_reset!
    end

    it 'serializes and deserializes an object exactly' do
      user = create :corp_pass_user
      serialized = CorpPass.serialize_user(user)
      deserialized = CorpPass.deserialize_user(serialized)
      expect(user).to eq(deserialized)
    end

    it 'sets up Rack to serialize and deserialize a user' do
      user = create :corp_pass_user
      login_as(user)
      env = env_with_params
      setup_rack(CorpPass::Test::RackHelper::SUCCESS_APP).call(env)

      setup_rack do |e|
        rack_user = CorpPass.user(e['warden'])
        expect(user).to eq(rack_user)
        CorpPass::Test::RackHelper::SUCCESS_APP.call(e)
      end.call(env)
    end
  end
end
