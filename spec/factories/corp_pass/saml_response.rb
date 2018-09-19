FactoryGirl.define do
  factory :saml_response, class: 'Saml::Response' do
    skip_create

    transient do
      xml_path 'spec/fixtures/corp_pass/saml_response.xml'
      has_attribute true
    end

    trait :invalid do
      transient do
        xml_path 'spec/fixtures/corp_pass/saml_response_invalid.xml'
      end
    end

    trait :no_assertion do
      transient do
        xml_path 'spec/fixtures/corp_pass/saml_response_no_assertion.xml'
        has_attribute false
      end
    end

    initialize_with { Saml::Response.parse File.read(xml_path) }

    after(:build) do |response, evaluator|
      if evaluator.has_attribute
        user = FactoryGirl.create(:corp_pass_user)
        user_xml = user.document.children[0].children.map(&:to_xml).join('')
        response.assertions.first.attribute_statement.attributes.first.attribute_values.first.content =
          Base64.encode64(user_xml)
      end
    end

    trait :encrypt_id do
      after(:build) do |response|
        key_descriptor = response.provider.find_key_descriptor(nil, Saml::Elements::KeyDescriptor::UseTypes::ENCRYPTION)
        response.assertion.subject.encrypted_id = Saml::Util.encrypt_name_id(response.assertion.subject._name_id,
                                                                             key_descriptor)
        response.assertion.subject._name_id = nil
      end
    end

    trait :encrypt_assertion do
      after(:build) do |response|
        certificate = response.provider.certificate(nil, Saml::Elements::KeyDescriptor::UseTypes::ENCRYPTION)
        response.encrypt_assertions(certificate)
      end
    end
  end
end
