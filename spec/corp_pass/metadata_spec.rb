require 'xmldsig'
require 'tempfile'

RSpec.describe CorpPass::Metadata do
  subject { described_class }
  before(:all) do
    @args = {
      entity_id: 'https://sp.example.com/saml/metadata',
      acs: 'https://sp.example.com/saml/acs',
      slo: 'https://sp.example.com/saml/slo',
      encryption_crt: 'spec/fixtures/corp_pass/saml_cert.crt',
      signing_key: 'spec/fixtures/corp_pass/saml_key.pem',
      signing_crt: 'spec/fixtures/corp_pass/saml_cert.crt'
    }

    @signing_certificate = OpenSSL::X509::Certificate.new(IO.read(@args[:signing_crt]))
  end

  specify ':generate generates a valid metadata with the right values' do
    metadata = subject.generate(**@args)

    valid = CorpPass::Metadata.verify_signature(metadata, @signing_certificate)
    expect(valid).to be true

    entity_descriptor = Saml::Elements::EntityDescriptor.parse(metadata, single: true)
    expect(entity_descriptor.entity_id).to eq(@args[:entity_id])
    expect(entity_descriptor.sp_sso_descriptor.assertion_consumer_services.map(&:location))
      .to eq([@args[:acs]])
    expect(entity_descriptor.sp_sso_descriptor.single_logout_services.map(&:location))
      .to eq([@args[:slo]])

    expected_uses = [Saml::Elements::KeyDescriptor::UseTypes::SIGNING,
                     Saml::Elements::KeyDescriptor::UseTypes::ENCRYPTION]
    expect(entity_descriptor.sp_sso_descriptor.key_descriptors.map(&:use)).to eq(expected_uses)

    signing_descriptor = entity_descriptor.sp_sso_descriptor.key_descriptors.find do |descriptor|
      descriptor.use == Saml::Elements::KeyDescriptor::UseTypes::SIGNING
    end
    expect(signing_descriptor.certificate.to_text).to eq(@signing_certificate.to_text)

    encryption_certificate = OpenSSL::X509::Certificate.new(IO.read(@args[:encryption_crt]))
    encryption_descriptor = entity_descriptor.sp_sso_descriptor.key_descriptors.find do |descriptor|
      descriptor.use == Saml::Elements::KeyDescriptor::UseTypes::ENCRYPTION
    end
    expect(encryption_descriptor.certificate.to_text).to eq(encryption_certificate.to_text)
  end

  specify ':generate can generate a document without a signature' do
    metadata = subject.generate(**@args.merge(sign_document: false))
    signed_document = Xmldsig::SignedDocument.new(metadata)
    expect(signed_document.signatures).to be_empty
  end

  specify ':generate handles sign_document if it is given as a string' do
    metadata = subject.generate(**@args.merge(sign_document: 'false'))
    signed_document = Xmldsig::SignedDocument.new(metadata)
    expect(signed_document.signatures).to be_empty

    metadata = subject.generate(**@args.merge(sign_document: 'true'))
    signed_document = Xmldsig::SignedDocument.new(metadata)
    expect(signed_document.signatures).to be_present
  end

  specify ':verify_signature verifies signature properly' do
    # The unicode characters are intentional
    unsigned = Saml::Response.new(in_response_to: 'αλ', status: Saml::TopLevelCodes::SUCCESS)

    signing_key = OpenSSL::PKey::RSA.new(IO.read(@args[:signing_key]))

    signed = Saml::Util.sign_xml(unsigned) do |data, signature_algorithm|
      signing_key.sign(CorpPass::Metadata.digest_method(signature_algorithm).new, data)
    end

    expect(CorpPass::Metadata.verify_signature(signed, @signing_certificate)).to be true

    # Force transcode from UTF-8 to ASCII, and replace the unicode character with something else
    invalid_signed = signed.encode(Encoding::ISO_8859_1, invalid: :replace, undef: :replace)
    expect(CorpPass::Metadata.verify_signature(invalid_signed, @signing_certificate)).to be false
  end

  specify ':generate_file generates a valid XML that passes signature verification' do
    tempfile = Tempfile.new('metadata.xml')
    CorpPass::Metadata.generate_file(out_file: tempfile.path, **@args)
    metadata = tempfile.read

    valid = CorpPass::Metadata.verify_signature(metadata, @signing_certificate)
    expect(valid).to be true

    tempfile.unlink
  end
end
