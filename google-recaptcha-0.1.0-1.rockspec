local plugin_name = "google-recaptcha"
local package_version = "0.1.0"
local rockspec_revision = "1"

package = plugin_name
version = package_version .. "-" .. rockspec_revision
source = {
  url = "git://github.com/gustoliv/kong-plugin-google-recaptcha",
  tag = "main"
}

description = {
  summary = "A Kong plugin to implement Google reCAPTCHA validation in services or routes",
  homepage = "https://github.com/gustoliv/kong-plugin-google-recaptcha",
  license = "Apache 2.0",
}

dependencies = {
  "lua-resty-http"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins."..plugin_name..".handler"] = "kong/plugins/"..plugin_name.."/handler.lua",
    ["kong.plugins."..plugin_name..".schema"] = "kong/plugins/"..plugin_name.."/schema.lua",
  }
}