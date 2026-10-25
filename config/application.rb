require_relative "boot"

require "rails/all"
require_relative "../app/middleware/catch_json_parse_errors"
# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

module SentriqAi
  class Application < Rails::Application
    # Ensure middleware directory is autoloaded
    config.autoload_paths << Rails.root.join('app', 'middleware')

    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 8.1
    # Ensure middleware directory is eager loaded (for production)
    config.eager_load_paths << Rails.root.join('app', 'middleware')
    # Insert middleware after framework initialization
    config.middleware.use ::CatchJsonParseErrors

    # Please, add to the `ignore` list any other `lib` subdirectories that do
    # not contain `.rb` files, or that should not be reloaded or eager loaded.
    # Common ones are `templates`, `generators`, or `middleware`, for example.
    config.autoload_lib(ignore: %w[assets tasks])

    # Configuration for the application, engines, and railties goes here.
    #
    # These settings can be overridden in specific environments using the files
    # in config/environments, which are processed later.
    #
    # config.time_zone = "Central Time (US & Canada)"
    # config.eager_load_paths << Rails.root.join("extras")
  end
end
