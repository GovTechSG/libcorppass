lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'corp_pass/version'

Gem::Specification.new do |spec|
  spec.name          = 'libcorppass'
  spec.version       = CorpPass::VERSION
  spec.authors       = ['Yong Wen Chua', 'Guoyou Ng']
  spec.email         = ['chua_yong_wen@ida.gov.sg', 'ng_guoyou@ida.gov.sg']
  spec.licenses      = ['LGPL']

  spec.summary       = 'A library to perform authentication with CorpPass for Ruby on Rails application'
  spec.description   = 'A wrapper around libsaml for applications to authenticate with Ruby on Rails'
  spec.homepage      = 'https://github.com/idagds/libcorppass'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>=2.2.0'

  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rubocop', '~> 0.38.0'
  spec.add_development_dependency 'rspec', '~> 3.4.0'
  spec.add_development_dependency 'factory_girl', '~> 4.5.0'
  spec.add_development_dependency 'webmock', '~> 1.24'
  spec.add_development_dependency 'actionpack', '~> 4.2'
  spec.add_development_dependency 'timecop', '~> 0.8'
  spec.add_development_dependency 'simplecov'

  spec.add_dependency 'activesupport', '>= 4.2'
  spec.add_dependency 'libsaml', '~> 3.0.9', '>= 2.21.3'
  spec.add_dependency 'nokogiri', '~> 1.6', '>= 1.6.8'
  spec.add_dependency 'xmlmapper', '~>0.7.1'
  spec.add_dependency 'warden', '~> 1.2', '>= 1.2.6'
end
