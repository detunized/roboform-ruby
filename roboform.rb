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

def login username, password, http
    nonce = generate_nonce

    # Step 1
    response = step1 username, nonce, http

    code = response.code
    if code == 401
    elsif code != 200
        raise "Step 1: Network request failed with HTTP status #{code}"
    end

    response.parsed_response
end

config = YAML.load_file "config.yaml"
http = Http.new

login config["username"], config["password"], http
