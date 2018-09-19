RSpec.describe CorpPass::User do
  subject { create(:corp_pass_user) }

  it 'should compare equality properly' do
    user = create(:corp_pass_user)
    expect(user).to eq(subject)
  end

  it 'should serialize and deserialize properly' do
    user = create(:corp_pass_user)
    serialized = user.serialize
    deserialized = CorpPass::User.deserialize(serialized)
    expect(deserialized).to eq(user)
  end

  it { expect(subject.xml).to eq(File.read('spec/fixtures/corp_pass/attribute_value.xml')) }
  it { expect(subject.info.account_type).to eq('User') }
  it { expect(subject.info.id).to eq('S1234567A') }
  it { expect(subject.info.country).to eq('SG') }
  it { expect(subject.info.entity_id).to eq('201000758R') }
  it { expect(subject.info.entity_status).to eq('Registered') }
  it { expect(subject.info.entity_type).to eq('UEN') }
  it { expect(subject.info.sp_holder?).to be true }
  it { expect(subject.given_eservices_count).to be 1 }
  it { expect(subject.info.full_name).to eq('Nelson Tan') }
  it { expect(subject.info.system_user_id).to eq('CP192') }
  it { expect(subject.info.non_uen_reg_no).to eq('NULL') }
  it { expect(subject.info.non_uen_country).to eq('NULL') }
  it { expect(subject.info.non_uen_name).to eq('NULL') }
  it { expect(subject.twofa?).to eq(false) }

  it 'should return the correct set of eservice_result' do
    foobar_service = subject.eservices[0]
    expect(foobar_service.id).to eq 'Foobar'
    expect(foobar_service.given_auth_count).to eq 2
    expect(foobar_service.auths.length).to eq 2

    expect(foobar_service.auths[0].start_date).to eq Date.new(2016, 1, 15)
    expect(foobar_service.auths[0].end_date).to eq Date.new(2016, 2, 15)
    expect(foobar_service.auths[0].entity_id_sub).to eq 'NULL'
    expect(foobar_service.auths[0].role).to eq 'Acceptor'
    expect(foobar_service.auths[0].parameters.length).to eq 0

    expect(foobar_service.auths[1].start_date).to eq Date.new(2015, 1, 15)
    expect(foobar_service.auths[1].end_date).to eq Date.new(2017, 2, 15)
    expect(foobar_service.auths[1].entity_id_sub).to eq 'foobar'
    expect(foobar_service.auths[1].role).to eq 'Viewer'
    expect(foobar_service.auths[1].parameters.length).to eq 2
    expect(foobar_service.auths[1].parameters[0].name).to eq 'foo'
    expect(foobar_service.auths[1].parameters[0].value).to eq 'bar'
    expect(foobar_service.auths[1].parameters[1].name).to eq 'lorem'
    expect(foobar_service.auths[1].parameters[1].value).to eq 'ipsum'
  end

  it 'should return eservices as a Hash' do
    hash = subject.eservices_to_h
    foobar_service = hash['Foobar']
    expect(foobar_service.auths.length).to eq 2
  end

  it 'should return auth results for an eservice' do
    auths = subject.auth_results_for('Foobar')
    expect(auths.length).to eq 2
    expect(auths[0].role).to eq 'Acceptor'
    expect(auths[1].role).to eq 'Viewer'
  end

  describe 'Validation' do
    context 'Valid document' do
      it { expect(subject.valid?).to be true }
      it { expect { subject.validate! }.to_not raise_error }
      it { expect(subject.send(:valid_root?)).to be true }
    end

    context 'Invalid document' do
      before(:all) do
        @invalid_user = create(:corp_pass_user, :invalid)
        @invalid_user.valid?
      end

      it { expect(@invalid_user.valid?).to be false }
      it { expect { @invalid_user.validate! }.to raise_error CorpPass::InvalidUser }
      it { expect(@invalid_user.errors.empty?).to be false }

      it 'validates badly formed XML documents properly' do
        invalid = described_class.new('<invalid>fail')
        expect(invalid.send(:xml_valid?)).to be false
        expect(invalid.valid?).to be false
        expect(invalid.errors).to include('Invalid XML Document: Premature end of data in tag invalid line 1')
      end

      it 'validates invalid roots correctly' do
        invalid_root = '<?xml version="1.0" encoding="UTF-8"?> <invalid>fail</invalid>'
        invalid = described_class.new(invalid_root)
        expect(invalid.send(:valid_root?)).to be false
        expect(invalid.errors).to include('Provided XML Document has an invalid root: invalid')
        expect(invalid.valid?).to be false
      end

      it 'validates the XSD correctly' do
        invalid_root = '<?xml version="1.0" encoding="UTF-8"?> <invalid>fail</invalid>'
        invalid = described_class.new(invalid_root)
        expect(invalid.send(:xsd_valid?)).to be false
        expect(invalid.valid?).to be false
        expect(invalid.errors).to include("XSD Validation failed: Element 'invalid': "\
                                          'No matching global declaration available for the validation root.')
      end

      it 'validates entity status correctly' do
        expect(@invalid_user.send(:valid_entity_status?)).to be false
        expect(@invalid_user.errors).to include('Invalid Entity Status MIA')
      end

      it 'validates the number Auth_Result_Set declared versus the actual number Auth_Result_Set rows' do
        expect(@invalid_user.errors).to include('1 <Auth_Result_Set> rows was declared, but 2 found')
      end
    end
  end
end
