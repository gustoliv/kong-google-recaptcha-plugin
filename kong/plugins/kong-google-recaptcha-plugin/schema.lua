local PLUGIN_NAME = "google-recaptcha"

return {
  name = PLUGIN_NAME,
  fields = {
    {
      config = {
        type = "record",
        fields = {
          {
            site_key = {
              type = "string",
              required = true,
              description = "Site Key from Google",
              referenceable = true
            }
          },
          {
            secret_key = {
              type = "string",
              required = true,
              description = "Secret Key from Google (API KEY for reCAPTCHA Enterprise)",
              referenceable = true
            },
          },
          {
            version = {
              type = "string",
              default = "v2",
              one_of = {
                "v2",
                "v3",
              },
              description = "Google reCAPTCHA version"
            },
          },
          {
            score_threshold = {
              type = "number",
              default = 0.8,
              between = {
                0,
                1
              },
              description = "Score threshold to validate against Google reCAPTCHA response"
            },
          },
          {
            enterprise = {
              type = "boolean",
              default = false,
              required = false,
              description =
              "Indicates whether to use reCAPTCHA Enterprise. Set to 'true' to enable, or 'false' to disable."
            },
          },
          {
            project_id = {
              type = "string",
              required = false,
              description =
              "Specifies the project ID for reCAPTCHA Enterprise, required if 'enterprise' is set to 'true'."
            },
          },
          {
            captcha_response_name = {
              type = "string",
              default = "g-recaptcha-response",
              required = false,
              description = "The name of the header or body property to look for Google reCAPTCHA response token"
            },
          },
          {
            error_message = {
              type = "string",
              default = "reCAPTCHA verification failed",
              required = false,
              description = "Set a custom error message to return when the Google reCAPTCHA validation is failed"
            },
          },
          {
            error_code = {
              type = "number",
              default = 403,
              required = false,
              description = "Set a custom error code to return when the Goole reCAPTCHA validation is failed"
            },
          },
          {
            display_errors = {
              type = "boolean",
              default = false,
              required = false,
              description = "When set to 'true', specific error details will be included in the failure responses returned to the client."
            },
          },
          {
            skip_recaptcha_for_internal_ips = {
              type = "boolean",
              default = false,
              required = false,
              description = "When set to 'true', reCAPTCHA validation will be skipped for requests from internal IP addresses (RFC1918). Set to 'true' to allow internal traffic to bypass reCAPTCHA verification."
            },
          },
          {
            action_name = {
              type = "string",
              required = true,
              description =
              "The reCAPTCHA action name defined in integration. This value must be equal to configured in the website, otherwise the plugin will block the request"
            }
          }
        },
        entity_checks = {
          {
            conditional = {
              if_field = "enterprise",
              if_match = { eq = true },
              then_field = "project_id",
              then_match = { required = true }
            }
          }
        }
      },
    },
  },
}
