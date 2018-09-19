require 'nokogiri'
require 'xmlmapper'
require 'corp_pass'
require 'corp_pass/util'

module CorpPass
  module Mapping
    class UserInfo
      include XmlMapper

      element :id, String, tag: 'CPUID'
      element :account_type, String, tag: 'CPAccType'
      element :country, String, tag: 'CPUID_Country'
      element :full_name, String, tag: 'CPUID_FullName'
      element :system_user_id, String, tag: 'CPSystemUID'
      element :entity_id, String, tag: 'CPEntID'
      element :entity_status, String, tag: 'CPEnt_Status'
      element :entity_type, String, tag: 'CPEnt_TYPE'
      element :is_sp_holder_raw, String, tag: 'ISSPHOLDER'
      element :non_uen_reg_no, String, tag: 'CPNonUEN_RegNo'
      element :non_uen_country, String, tag: 'CPNonUEN_Country'
      element :non_uen_name, String, tag: 'CPNonUEN_Name'

      # Maps the <ISSPHOLDER> field with the mapping { 'yes' => true, 'no' => false }
      # @return [Boolean] Whether this {User} is also a SingPass holder
      def sp_holder?
        CorpPass::Util.string_to_boolean(@is_sp_holder_raw, true_string: 'yes', false_string: 'no')
      end
    end

    module AuthAccess
      class AuthParameter
        include XmlMapper

        tag 'Parameter'
        content :value
        attribute :name, String
      end

      class Auth
        include XmlMapper

        tag 'Row'
        element :entity_id_sub, String, tag: 'CPEntID_SUB'
        element :role, String, tag: 'CPRole'
        element :start_date, Date, tag: 'StartDate'
        element :end_date, Date, tag: 'EndDate'
        has_many :parameters, AuthParameter, tag: 'Parameter'
      end

      class EService
        include XmlMapper

        tag 'ESrvc_Result'
        element :id, String, tag: 'CPESrvcID'
        element :given_auth_count, Integer, tag: 'Auth_Result_Set/Row_Count'
        has_many :auths, Auth, tag: 'Auth_Result_Set/Row'
      end

      class AuthAccess
        include XmlMapper

        tag 'AuthAccess'
        element :given_eservices_count, Integer, tag: 'Result_Set/ESrvc_Row_Count'
        has_many :eservices, EService, tag: 'Result_Set/ESrvc_Result'
      end
    end

    # This module defines the mapping from an AuthAccess XML fragment to a
    # {CorpPass::User} object
    module User
      def self.included(u)
        u.tag 'AttributeValue'
        u.element :given_eservices_count, Integer, tag: 'AuthAccess/Result_Set/ESrvc_Row_Count'
        u.has_many :eservices, AuthAccess::EService, tag: 'AuthAccess/Result_Set/ESrvc_Result'
        u.element :info, UserInfo, tag: 'UserInfo'
      end

      # Convenience method to return e-services associated with this +User+.
      #
      # @return [Hash] All e-services as a +Hash+ with e-service ID
      #                as the key and e-service details as the value
      def eservices_to_h
        Hash[@eservices.map { |eservice| [eservice.id, eservice] }]
      end

      # Convenience method to return auth info associated with a particular e-service ID for this +User+.
      #
      # @param eservice_id [String] the e-service ID to obtain auth info for this +User+
      #
      # @return [Array] An +Array+ of +AuthResult+ for the given +eservice_id+ associated with this +User+
      def auth_results_for(eservice_id)
        eservices_to_h[eservice_id].auths
      end
    end
  end

  # An +Error+ object raised on creation of a {User} with invalid XML.
  #
  # See: {User}
  # @attr_reader xml [String]
  class InvalidUser < Error
    attr_reader :xml

    # @param message [String]
    # @param xml [String]
    def initialize(message, xml)
      super(message)
      @xml = xml
    end
  end

  class User
    include XmlMapper
    include CorpPass::Mapping::User
    include CorpPass::Notification

    attr_reader :xml
    attr_reader :errors

    # @param xml [String]
    def initialize(xml = nil, options = {})
      # XmlMapper creates objects with the same constructor so we need this check here
      # `xml` is `nil` when XmlMapper does its magic
      if !xml.nil?
        @errors = []
        @xml = xml
        @twofa = options[:twofa]
        parse(xml) if xml_valid?
      end
    end

    def ==(other)
      other.class == self.class && other.xml == xml && other.twofa? == twofa?
    end
    alias eql? ==

    # Returns whether this {User} was authenticated with 2FA.
    # @return [Boolean]
    def twofa? # rubocop:disable Style/TrivialAccessors # Can't have `?` in accessors
      @twofa
    end

    # Returns the +Nokogiri::XML+ document backing this {User}. The document is memoized.
    # @return [Nokogiri::XML]
    def document
      @document ||= Nokogiri::XML(xml)
    end

    # Returns the +Nokogiri::XML::Schema+ backing the user. The XSD is memoized.
    # @return [Nokogiri::XML::Schema]
    def xsd
      # File I/O considered expensive
      @xsd_memo ||= Nokogiri::XML::Schema(File.read(File.join(File.dirname(__FILE__), 'xml', 'AttributeValue.xsd')))
    end

    # Returns the XML document backing this {User}.
    # @return [Array<String>] An array of [xml, twofa?] representing the serialized user
    def serialize
      [xml, twofa?]
    end

    # Deserializes a {User} from an XML document.
    # @param dumped_array [Array] an +Array+ with the serialized {User} as the first element
    #                             and whether the user was authenticated with 2FA as the second element.
    def self.deserialize(dumped_array)
      xml, twofa = dumped_array
      new(xml, twofa: twofa)
    end

    # Checks whether this user is backed by a valid XML
    # @return [Boolean] Whether this +User+ is valid
    def valid?
      @errors = []
      return false unless xml_valid?
      return false unless xsd_valid?
      valid_root?
      valid_entity_status?
      valid_eservice_results?

      errors.each { |error| notify(CorpPass::Events::USER_VALIDATION_FAILURE, error) }
      errors.empty?
    end

    # Validates this {User}, raising an {InvalidUser} error if invalid.
    # @return [Boolean] `true` if valid, else an {InvalidUser} error is raised
    def validate!
      unless valid?
        # Disabling the cop because they cannot make up their mind on this!
        # And `fail` does not allow for extra parameters
        raise CorpPass::InvalidUser.new(@errors.join('; '), xml) # rubocop:disable Style/SignalException
      end
      true
    end

    private

    # Returns whether the XML backing this +User+ has errors. Note that this method does not
    # validate the XML against the namespace defined in the specification due to inconsistencies
    # found between that and the actual XML response.
    #
    # Also adds any errors found in the XML to the instance variable +@errors+.
    #
    # @return [Boolean] Whether the XML is valid
    def xml_valid?
      valid = document.errors.empty?
      @errors << "Invalid XML Document: #{document.errors.map(&:to_s).join('; ')}" unless valid
      valid
    end

    # Returns whether the XML backing this +User+ conforms to the expected AuthAccess XSD.
    #
    # Also adds any errors found in the XML to the instance variable +@errors+.
    #
    # @return [Boolean] Whether the XML validates against the expected AuthAccess XSD
    def xsd_valid?
      xsd_errors = xsd.validate(document)
      @errors << "XSD Validation failed: #{xsd_errors.map(&:message).join('; ')}" unless xsd_errors.empty?
      xsd_errors.empty?
    end

    # Returns whether the XML backing this +User+ has a valid XML root element.
    #
    # Also adds any errors found in the XML to the instance variable +@errors+.
    #
    # @return [Boolean]
    def valid_root?
      valid = (document.root.name == CorpPass::Response::ATTRIBUTE_VALUE_NAME)
      @errors << "Provided XML Document has an invalid root: #{document.root.name}" unless valid
      valid
    end

    # Returns whether the XML backing this +User+ has a valid entity status.
    #
    # Also adds any errors found in the XML to the instance variable +@errors+.
    #
    # @return [Boolean]
    def valid_entity_status?
      valid = %w(Registered De-Registered Withdrawn).include?(info.entity_status)
      @errors << "Invalid Entity Status #{info.entity_status}" unless valid
      valid
    end

    # Sanity check: checks whether the given <Row_Count> for each e-service Auth_Result_Set
    # matches length of parsed output
    def valid_eservice_results?
      valid = eservices.map do |svc|
        valid_row_count = svc.auths.length == svc.given_auth_count
        unless valid_row_count
          @errors << "#{svc.given_auth_count} <Auth_Result_Set> rows was declared, but #{svc.auths.length} found"
        end
        valid_row_count
      end.all?

      valid
    end
  end
end
