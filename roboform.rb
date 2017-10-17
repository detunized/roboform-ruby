#!/usr/bin/env ruby

# Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "yaml"
require "httparty"

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

def login username, password, http
end

config = YAML.load_file "config.yaml"
http = Http.new

login config["username"], config["password"], http
