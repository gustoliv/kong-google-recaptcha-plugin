local http = require "resty.http"
local json = require "cjson.safe"

local GoogleRecaptchaPlugin = {
  PRIORITY = 920,
  VERSION = "0.1.0",
}

local kong = kong

local function record_span_error(span, message)
  span:set_status(2)
  span:record_error(message)
  span:finish()
end

local function decode_json(body)
  local decoded_body, err = json.decode(body)
  if not decoded_body then
    return nil, string.format("Error decoding JSON: %s", err or "unknown")
  end
  return decoded_body
end

local function start_tracing_span(name)
  local root_span = kong.tracing.active_span()
  return kong.tracing.start_span(name, {
    start_time_ns = ngx.now() * 1e9,
    span_kind = 3,
    parent = root_span
  })
end

local function is_rfc1918_ip(ip)
  local octets = {}
  for octet in ip:gmatch("(%d+)") do
    table.insert(octets, tonumber(octet))
  end

  if #octets ~= 4 then
    return false
  end

  local a, b = octets[1], octets[2]
  if (a == 10) or
      (a == 172 and b >= 16 and b <= 31) or
      (a == 192 and b == 168) then
    return true
  end

  return false
end

local function validate_enterprise(config, g_captcha_res, remote_ip, user_agent, referer)
  local query_params = {
    key = config.secret_key
  }

  local body = {
    event = {
      token = g_captcha_res,
      siteKey = config.site_key,
      expectedAction = config.action_name,
      userAgent = user_agent,
      userIpAddress = remote_ip,
    }
  }

  local encoded_body = json.encode(body)

  local span = start_tracing_span("google-recaptcha-enterprise-response")
  local httpc = http.new()
  local res, err = httpc:request_uri(config.api_server, {
    method = 'POST',
    query = query_params,
    headers = {
      ["Content-Type"] = "application/json",
      ["Content-Length"] = #encoded_body,
      ["Referer"] = referer
    },
    body = encoded_body
  })

  if not res then
    record_span_error(span, string.format('Error when calling Google reCAPTCHA Enterprise API: %s', err))
    return nil, string.format('Error when calling Google reCAPTCHA Enterprise API: %s', err)
  end

  local response_body, decode_err = decode_json(res.body)
  if not response_body then
    record_span_error(span, decode_err)
    return nil, decode_err
  end

  if res.status ~= 200 then
    record_span_error(span, string.format("Unexpected HTTP status code from reCAPTCHA API: %s", res.status))
    return nil, string.format("Unexpected HTTP status code from reCAPTCHA API: %s", res.status)
  end

  if not response_body.tokenProperties or not response_body.tokenProperties.valid then
    record_span_error(span,
      response_body.tokenProperties and response_body.tokenProperties.invalidReason or "Unknown error")
    return false, "Invalid token"
  end


  if response_body.tokenProperties.action ~= config.action_name then
    local action_mismatch = string.format("Action mismatch: expected '%s', got '%s'",
      config.action_name, response_body.tokenProperties.action)
    record_span_error(span, action_mismatch)
    return false, action_mismatch
  end

  if response_body.riskAnalysis and response_body.riskAnalysis.reasons then
    for k, v in ipairs(response_body.riskAnalysis.reasons) do
      local span_attribute_name = string.format("recaptcha.riskAnalysis.reasons.%s", k)
      local span_attribute_value = type(v) == "table" and table.concat(v, ", ") or v
      span:set_attribute(span_attribute_name, span_attribute_value)
    end
  end

  span:set_attribute("recaptcha_response_body", res.body)
  span:set_attribute("score", response_body.riskAnalysis.score)
  span:set_attribute("valid", response_body.tokenProperties.valid)
  span:set_attribute("user_agent", user_agent)
  span:set_attribute("action", response_body.tokenProperties.action)
  span:set_attribute("expected_action", config.action_name)
  span:set_status(1)
  span:finish()
  return true, nil, response_body.riskAnalysis.score
end

local function validate_free(config, g_captcha_res, remote_ip)
  local query_params = {
    secret = config.secret_key,
    response = g_captcha_res,
    remoteip = remote_ip,
  }

  local span = start_tracing_span("google-recaptcha-free-response")
  local httpc = http.new()
  local res, err = httpc:request_uri(config.api_server, {
    method = 'POST',
    query = query_params,
    headers = {
      ["Content-Type"] = "application/json"
    }
  })

  if not res then
    record_span_error(span, err)
    return nil, string.format("Error calling Google reCAPTCHA Free API: %s", err)
  end

  local response_body, decode_err = decode_json(res.body)
  if not response_body then
    record_span_error(span, decode_err)
    return nil, decode_err
  end

  if not response_body.success then
    local error_message = table.concat(response_body["error-codes"] or {}, ", ")
    record_span_error(span, error_message)
    return false, error_message
  end

  if response_body.action ~= config.action_name then
    local action_mismatch = string.format("Action mismatch: expected '%s', got '%s'",
      config.action_name, response_body.action)
    record_span_error(span, action_mismatch)
    return false, action_mismatch
  end

  span:set_attribute("recaptcha_response_body", res.body)
  span:set_attribute("score", response_body.score)
  span:set_attribute("valid", response_body.success)
  span:set_attribute("action", response_body.action)
  span:set_attribute("expected_action", config.action_name)
  span:set_status(1)
  span:finish()
  return true, nil, response_body.score
end

local function validate(config, g_captcha_res, remote_ip, user_agent, referer)
  if config.enterprise then
    return validate_enterprise(config, g_captcha_res, remote_ip, user_agent, referer)
  else
    return validate_free(config, g_captcha_res, remote_ip)
  end
end

function GoogleRecaptchaPlugin:access(config)

  local remote_ip = kong.client.get_forwarded_ip() or kong.client.get_ip()
  kong.log.debug(string.format("Client IP: %s", remote_ip))

  if config.skip_recaptcha_for_internal_ips and is_rfc1918_ip(remote_ip) then
    kong.log.debug("Skipping reCAPTCHA validation for IP " .. remote_ip)
    return
  end

  if config.enterprise then
    if not config.project_id or config.project_id == "" then
      return kong.response.error(config.error_code, "The 'project_id' must be set when using reCAPTCHA Enterprise.",
        { ["Content-Type"] = "application/json" })
    end
    config.api_server = string.format("https://recaptchaenterprise.googleapis.com/v1/projects/%s/assessments",
      config.project_id)
  else
    config.api_server = "https://www.google.com/recaptcha/api/siteverify"
  end

  kong.log.debug(
    string.format(
      "Validating a recaptcha secret: version %s for site key %s at server %s using header name %s ",
      config.version,
      config.site_key,
      config.api_server,
      config.captcha_response_name
    )
  )

  local g_captcha_res = kong.request.get_header(config.captcha_response_name)
  if not g_captcha_res then
    local body = kong.request.get_body()
    if body then
      g_captcha_res = body[config.captcha_response_name]
    end
  end
  if not g_captcha_res then
    return kong.response.error(config.error_code, "Missing reCAPTCHA token.",
    { ["Content-Type"] = "application/json" })
  end

  local referer = kong.request.get_header("referer")
  local user_agent = kong.request.get_header("user-agent")

  if config.enterprise and not referer then
    return kong.response.error(config.error_code, "Missing 'Referer' header.",
      { ["Content-Type"] = "application/json" })
  end

  kong.log.debug(
    string.format("Validating a recaptcha secret: retrieved captcha response %s ", g_captcha_res)
  )

  local status, errs, score = validate(config, g_captcha_res, remote_ip, user_agent, referer)

  kong.log.inspect({ status, errs, score })

  local error_message = config.error_message

  if (config.display_errors) then
    if errs then
      error_message = string.format("%s. Details: %s", error_message, errs)
    end
  end

  if not status then
    return kong.response.error(config.error_code, error_message, { ["Content-Type"] = "application/json" })
  elseif config.version == "v3" and config.score_threshold and score < config.score_threshold then
    if (config.display_errors) then
      local score_error = string.format("Score below threshold: expected >= %.2f, got %.2f", config.score_threshold,
        score)
      error_message = string.format("%s. Score Error: %s", error_message, score_error)
    end
    kong.log.debug(error_message)
    return kong.response.error(config.error_code, error_message, { ["Content-Type"] = "application/json" })
  end
end

return GoogleRecaptchaPlugin
