#!/usr/bin/env ruby

# Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "base64"
require "httparty"
require "securerandom"
require "uri"
require "yaml"

DISABLE_RANDOM = true

class Http
    include HTTParty

    def initialize
        @post_headers = {}
    end

    def post url, args, headers = {}
        self.class.post url, {
            body: args,
            headers: @post_headers.merge(headers)
        }
    end
end

def d64 s
    Base64.decode64 s
end

def e64 s
    Base64.strict_encode64 s
end

# JavaScript encodeURI equivalent
# See: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURI
def encodeURI s
    URI.escape s, /[^A-Za-z0-9;,\/?:@&=+$\-_.!~*'()#]/
end

def generate_nonce length = 16
    if DISABLE_RANDOM
        "-DeHRrZjC8DZ_0e8RGsisg"
    else
        b64 = Base64.urlsafe_encode64 SecureRandom.random_bytes length
        b64.sub /\=*$/, ""
    end
end

def step1_authorization_header username, nonce
    encoded_username = encodeURI username
    data = e64 "n,,n=#{encoded_username},r=#{nonce}"
    %Q{SibAuth realm="RoboForm Online Server",data="#{data}"}
end

def step1 username, nonce, http
    encoded_username = encodeURI username
    http.post "https://online.roboform.com/rf-api/#{encoded_username}?login", {}, {
        Authorization: step1_authorization_header(username, nonce)
    }
end

def parse_auth_info header
    realm, params = header.split " "

    parsed_params = params
        .split(",")
        .map { |i| i =~ /(\w+)\="(.*)"/; [$1, $2] }
        .to_h

    sid = parsed_params["sid"]
    data = d64 parsed_params["data"]

    parsed_data = data
        .split(",")
        .map { |i| i =~ /(\w+)\=(.*)/; [$1, $2] }
        .to_h

    {
        sid: sid,
        data: data,
        nonce: parsed_data["r"],
        salt: d64(parsed_data["s"]),
        iterations: parsed_data["i"].to_i,
        md5?: parsed_data.fetch("o", "").include?("pwdMD5")
    }
end

def login username, password, http
    nonce = generate_nonce

    # Step 1
    response = step1 username, nonce, http

    code = response.code
    if code == 401
        auth_info = parse_auth_info response.headers["WWW-Authenticate"]
    elsif code != 200
        raise "Step 1: Network request failed with HTTP status #{code}"
    end

    response.parsed_response
end

#
# Tests
#

def check expression, message = ""
    raise message if !expression
end

def test_parse_auth_info
    auth_info = parse_auth_info 'SibAuth sid="6Ag93Y02vihucO9IQl1fbg",data' +
                                '="cj0tRGVIUnJaakM4RFpfMGU4UkdzaXNnTTItdGp' +
                                'nZi02MG0tLUZCaExRMjZ0ZyxzPUErRnQ4VU02NzRP' +
                                'Wk9PalVqWENkYnc9PSxpPTQwOTY="'
    check auth_info[:sid] == "6Ag93Y02vihucO9IQl1fbg"
    check auth_info[:data] == "r=-DeHRrZjC8DZ_0e8RGsisgM2-tjgf-60m--FBhLQ26tg,s=A+Ft8UM674OZOOjUjXCdbw==,i=4096"
    check auth_info[:nonce] == "-DeHRrZjC8DZ_0e8RGsisgM2-tjgf-60m--FBhLQ26tg"
    check auth_info[:salt] == d64("A+Ft8UM674OZOOjUjXCdbw==")
    check auth_info[:iterations] == 4096
    check auth_info[:md5?] == false
end

#
# main
#

config = YAML.load_file "config.yaml"
http = Http.new

# Poor man's tests
test_parse_auth_info

login config["username"], config["password"], http
