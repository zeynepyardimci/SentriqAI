class CatchJsonParseErrors
  def initialize(app)
    @app = app
  end

  def call(env)
    @app.call(env)
  rescue ActionDispatch::Http::Parameters::ParseError => e
    Rails.logger.error "CatchJsonParseErrors: #{e.message}"
    body = { success: false, error: "Malformed JSON payload: #{e.message}" }.to_json
    [400, { "Content-Type" => "application/json" }, [body]]
  end
end
