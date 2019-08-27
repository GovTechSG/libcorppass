module NricHelper
  def self.mask_xml_nric(user_info)
    doc = Nokogiri::XML(user_info)
    if doc.at_xpath('//CPUID').present?
      nric_value = doc.at_xpath('//CPUID').content
      doc.at_xpath('//CPUID').content = mask_nric(nric_value)
      doc.to_xml
    end
  end

  def self.mask_nric(to_mask)
    to_mask.gsub(/.(?=.{4})/, 'X')
  end

  def self.mask_nric_slo_request(request)
    doc = Nokogiri::XML(request.to_xml)
    if doc.at_xpath('//saml:NameID').present?
      nric_value = doc.at_xpath('//saml:NameID').content
      doc.at_xpath('//saml:NameID').content = mask_nric(nric_value)
      doc.to_xml
    end
  end
end
