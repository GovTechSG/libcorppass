require 'timecop'

RSpec.describe CorpPass::Response do
  before(:all) do
    Timecop.freeze(Time.utc(2015, 11, 30, 4, 45))
    sp = 'https://sp.example.com/saml/metadata'
    Saml.current_provider = Saml.provider(sp)
    CorpPass.configuration.sp_entity = sp
  end

  after(:all) do
    Timecop.return
    CorpPass::Test::Config.reset_configuration!
  end

  context 'Valid SAML Response' do
    subject do
      saml_response = create(:saml_response, :encrypt_id, :encrypt_assertion)
      CorpPass::Response.new saml_response
    end

    it { expect(subject.valid?).to be true }
    it { expect(subject.success?).to be true }
    it { expect(subject.errors).to be_empty }
    it { expect(subject.assertions).to all(be_a(Saml::Assertion)) }
    it { expect(subject.assertion).to be_a(Saml::Assertion) }
    it { expect(subject.attribute_statement).to be_a(Saml::Elements::AttributeStatement) }
    it { expect(subject.subject).to be_a(Saml::Elements::Subject) }
    it { expect(subject.name_id).to eq('S1234567A') }
    it { expect { subject.attribute_value }.to_not raise_error }
    it { expect { subject.cp_user }.to_not raise_error }
    it 'decrypts the assertion successfully' do
      expect(subject.saml_response.encrypted_assertions).to be_empty
      expect(subject.assertion).to be_a(Saml::Assertion)
    end
    it { expect(subject.authn_statement).to all(be_a(Saml::Elements::AuthnStatement)) }
    it { expect(subject.authn_context_class_refs).to eq([Saml::ClassRefs::PASSWORD]) }

    describe '2FA' do
      it { expect(subject.twofa?).to be false }
      it 'returns true when presented with the appropriate AuthnContextClassRef' do
        expect(subject).to receive(:authn_context_class_refs)
          .and_return([Saml::ClassRefs::PASSWORD, Saml::ClassRefs::MOBILE_TWO_FACTOR_UNREGISTERED])
        expect(subject.twofa?).to be true
      end
    end
  end

  context 'Invalid SAML Response' do
    subject do
      saml_response = create(:saml_response, :invalid)
      CorpPass::Response.new saml_response
    end

    it { expect(subject.valid?).to be false }
    it { expect(subject.errors).to_not be_empty }
    it 'validates the destination properly' do
      expect(subject.errors).to include('The destination was https://sp.example.com/saml/foobar, '\
                                         'but the ACS is at https://sp.example.com/saml/acs')
    end

    it 'validates the <samlp:Response> issuer properly' do
      expected = 'The issuer for <samlp:Response> was '\
                 'https://idp.example.com/saml2/idp/foobar '\
                 'but the issuer entity expected should be '\
                 'https://idp.example.com/saml2/idp/metadata'
      expect(subject.errors).to include(expected)
    end

    it 'validates successful status correctly' do
      expected = 'SamlResponse status was not success: <?xml version="1.0"?>
<Status>
  <StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester">
    <StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/>
  </StatusCode>
</Status>
'
      expect(subject.errors).to include(expected)
    end

    it 'validates the number of assertions properly' do
      expect(subject.errors).to include('More than one assertions found: 2')
    end

    it 'validates the <saml:Assertion> issuer properly' do
      expected = 'The issuer for <saml:Assertion> was '\
                 'https://idp.example.com/saml2/idp/foobar '\
                 'but the issuer entity expected should be '\
                 'https://idp.example.com/saml2/idp/metadata'
      expect(subject.errors).to include(expected)
    end

    it 'validates the condition timestamps properly' do
      expected = 'For saml:Assertion/saml:Conditions, time now is 2015-11-30 04:45:00 UTC, '\
                 'and is before 2099-11-30 04:42:01 UTC'
      expect(subject.errors).to include(expected)
    end

    it 'validates the audience properly' do
      expect(subject.errors).to include('Missing SP entity from audiences')
    end

    it 'validates subject confirmations properly' do
      # The subject confirmations in the fixtures have been constructed to fail all the three checks performed
      # in this validation individually
      expect(subject.errors).to include('No valid subject confirmation found')
    end

    it 'raises an exception if SAML assertion is missing' do
      expect { CorpPass::Response.new(create(:saml_response, :no_assertion)) }
        .to raise_error(CorpPass::MissingAssertionError)
    end
  end
end
