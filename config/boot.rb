ENV["BUNDLE_GEMFILE"] ||= File.expand_path("../Gemfile", __dir__)

require "bundler/setup" # Set up gems listed in the Gemfile.
begin
  require "bootsnap/setup" unless Gem.win_platform?
rescue LoadError, StandardError
  # Fallback gracefully if bootsnap encounters non-ASCII Windows path issues
end

# Load .env variables if .env exists
env_file = File.expand_path("../.env", __dir__)
if File.exist?(env_file)
  File.foreach(env_file) do |line|
    line = line.strip
    next if line.empty? || line.start_with?("#")
    key, val = line.split("=", 2)
    ENV[key.strip] ||= val.to_s.strip.gsub(/\A["']|["']\z/, "") if key
  end
end
