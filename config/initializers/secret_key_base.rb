# frozen_string_literal: true

# In production, allow SECRET_KEY_BASE to be supplied as an environment variable.
# This avoids the need for config/credentials.yml.enc to contain secret_key_base,
# which would otherwise require sharing the master key and regenerating credentials.
#
# Render (and similar platforms) inject SECRET_KEY_BASE as an env var.
# Rails 7.1+ already supports this natively; this initializer is a safety net
# for older-style credential setups where secret_key_base might be missing.
if Rails.env.production? && ENV["SECRET_KEY_BASE"].present?
  Rails.application.credentials.secret_key_base = ENV["SECRET_KEY_BASE"]
end
