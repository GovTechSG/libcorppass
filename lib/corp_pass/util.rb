module CorpPass
  module Util
    # Converts <tt>['true', 'false']</tt> +String+ objects into +Boolean+ objects.
    # @return [Boolean]
    def self.string_to_boolean(value, true_string: 'true', false_string: 'false')
      return value if [true, false].include? value
      return true if value.casecmp(true_string).zero?
      return false if value.casecmp(false_string).zero?
      fail ArgumentError, "Unable to convert #{value} to boolean"
    end

    def self.throw_warden(type, scope, others = {})
      message = { type: type, scope: scope }.merge(others)
      throw :warden, message
    end

    def self.throw_exception(exception, scope, others = {})
      CorpPass::Util.throw_warden(:exception, scope, exception: exception, **others)
    end

    # From a Rack environment Hash, get the values thrown by warden
    def self.warden_options(env)
      return nil unless env.key?('warden.options')
      env['warden.options']
    end

    def self.authentication_error?(warden_options)
      !warden_options.nil? && warden_options[:type] == :exception
    end
  end
end
