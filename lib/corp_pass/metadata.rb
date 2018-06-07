require 'xmldsig'
require 'openssl'
require 'saml'

module CorpPass
  module Metadata
    def self.generate(entity_id:, acs:, slo:, # rubocop:disable Metrics/ParameterLists
                      encryption_crt:, signing_key:, signing_crt:, sign_document: true)
      entity_descriptor = Saml::Elements::EntityDescriptor.new(entity_id: entity_id)
      entity_descriptor.sp_sso_descriptor = make_sp_descriptor(acs, encryption_crt, signing_crt, slo)

      if sign_document == true || sign_document == 'true'
        sign(entity_descriptor, signing_crt, signing_key)
      else
        entity_descriptor.to_xml
      end
    end

    def self.generate_file(**args)
      out_file = args.delete(:out_file)
      write_xml(generate(**args), out_file)
      nil
    end

    def self.verify_signature(signed_xml, signing_certificate)
      signed_document = Xmldsig::SignedDocument.new(signed_xml)
      signed_document.validate do |signature, data, signature_algorithm|
        signing_certificate.public_key.verify(digest_method(signature_algorithm).new,
                                              signature, data)
      end
    end

    def self.digest_method(signature_algorithm)
      digest = signature_algorithm && signature_algorithm =~ /sha(.*?)$/i && Regexp.last_match(1).to_i
      case digest
      when 256 then
        OpenSSL::Digest::SHA256
      else
        OpenSSL::Digest::SHA1
      end
    end

    def self.sign(document, signing_crt, signing_key)
      key = OpenSSL::PKey::RSA.new(IO.read(signing_key))
      signed = Saml::Util.sign_xml(document) do |data, signature_algorithm|
        key.sign(digest_method(signature_algorithm).new, data)
      end

      unless verify_signature(signed, OpenSSL::X509::Certificate.new(IO.read(signing_crt)))
        fail 'Signature verification failed'
      end
      signed
    end
    private_class_method :sign

    def self.make_sp_descriptor(acs, encryption_crt, signing_crt, slo)
      sp_descriptor = Saml::Elements::SPSSODescriptor.new(authn_requests_signed: true, want_assertions_signed: true)
      sp_descriptor.add_assertion_consumer_service(Saml::ProtocolBinding::HTTP_ARTIFACT, acs, 0, true)
      sp_descriptor.single_logout_services << Saml::ComplexTypes::SSODescriptorType::SingleLogoutService.new(
        binding: Saml::ProtocolBinding::HTTP_REDIRECT, location: slo
      )

      sp_descriptor.key_descriptors << make_key_descriptor(signing_crt,
                                                           Saml::Elements::KeyDescriptor::UseTypes::SIGNING)
      sp_descriptor.key_descriptors << make_key_descriptor(encryption_crt,
                                                           Saml::Elements::KeyDescriptor::UseTypes::ENCRYPTION)
      sp_descriptor
    end
    private_class_method :make_sp_descriptor

    def self.make_key_descriptor(crt, use)
      key_info = Saml::Elements::KeyInfo.new(IO.read(crt))
      Saml::Elements::KeyDescriptor.new(use: use, key_info: key_info)
    end
    private_class_method :make_key_descriptor

    def self.write_xml(xml, path)
      File.open(path, 'w:UTF-8') do |f|
        f.write xml
      end
    end
    private_class_method :write_xml
  end
end
