#!/usr/bin/env ruby

# Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "base64"
require "httparty"
require "securerandom"
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

def generate_nonce length = 16
    if DISABLE_RANDOM
        "-DeHRrZjC8DZ_0e8RGsisg"
    else
        b64 = Base64.urlsafe_encode64 SecureRandom.random_bytes length
        b64.sub /\=*$/, ""
    end
end

def login username, password, http
    username = URI.escape username
    nonce = generate_nonce
end

config = YAML.load_file "config.yaml"
http = Http.new

login config["username"], config["password"], http
