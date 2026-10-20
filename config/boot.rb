ENV["BUNDLE_GEMFILE"] ||= File.expand_path("../Gemfile", __dir__)

require "bundler/setup" # Set up gems listed in the Gemfile.
begin
  require "bootsnap/setup" unless Gem.win_platform?
rescue LoadError, StandardError
  # Fallback gracefully if bootsnap encounters non-ASCII Windows path issues
end
