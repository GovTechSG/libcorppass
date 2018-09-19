FactoryGirl.define do
  factory :corp_pass_user, class: 'CorpPass::User' do
    skip_create

    transient do
      xml_path 'spec/fixtures/corp_pass/attribute_value.xml'
    end

    trait :invalid do
      transient do
        xml_path 'spec/fixtures/corp_pass/attribute_value_invalid.xml'
      end
    end

    initialize_with { new File.read(xml_path), twofa: false }
  end
end
