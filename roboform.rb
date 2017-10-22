#!/usr/bin/env ruby

# Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

require "base64"
require "httparty"
require "openssl"
require "securerandom"
require "uri"
require "yaml"

DISABLE_RANDOM = true

class Http
    include HTTParty

    def initialize
        @get_headers = {}
        @post_headers = {}
    end

    def get url, headers = {}
        self.class.get url, {
            headers: @get_headers.merge(headers)
        }
    end

    def post url, args, headers = {}
        self.class.post url, {
            body: args,
            headers: @post_headers.merge(headers)
        }
    end
end

#
# Utils
#

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

#
# Crypto
#

def hmac key, message
    OpenSSL::HMAC.digest "sha256", key, message
end

#
# Login
#

def generate_nonce length = 16
    if DISABLE_RANDOM
        "-DeHRrZjC8DZ_0e8RGsisg"
    else
        b64 = Base64.urlsafe_encode64 SecureRandom.random_bytes length
        b64.sub /\=*$/, ""
    end
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

def hash_password password, auth_info
    if auth_info[:md5?]
        password = Digest::MD5.digest password
    end

    OpenSSL::PKCS5.pbkdf2_hmac password,
                               auth_info[:salt],
                               auth_info[:iterations],
                               32,
                               "sha256"
end

def compute_client_key hashed_password
    hmac hashed_password, "Client Key"
end

def compute_client_hash client_key
    Digest::SHA256.digest client_key
end

def step1_authorization_header username, nonce
    encoded_username = encodeURI username
    data = e64 "n,,n=#{encoded_username},r=#{nonce}"

    %Q{SibAuth realm="RoboForm Online Server",data="#{data}"}
end

def step2_authorization_header username, password, nonce, auth_info
    hashed_password = hash_password password, auth_info
    client_key = compute_client_key hashed_password
    client_hash = compute_client_hash client_key

    encoded_username = encodeURI username
    hashing_material = "n=#{encoded_username},r=#{nonce},#{auth_info[:data]},c=biws,r=#{auth_info[:nonce]}"
    hashed = hmac client_hash, hashing_material

    proof = e64 client_key.bytes.zip(hashed.bytes).map { |i| i[0] ^ i[1] }.pack "c*"
    data = e64 "c=biws,r=#{auth_info[:nonce]},p=#{proof}"

    %Q{SibAuth sid="#{auth_info[:sid]}",data="#{data}"}
end

def auth_step username, header, http
    encoded_username = encodeURI username
    http.post "https://online.roboform.com/rf-api/#{encoded_username}?login", {}, {
        Authorization: header
    }
end

def step1 username, nonce, http
    auth_step username,
              step1_authorization_header(username, nonce),
              http
end

def step2 username, password, nonce, auth_info, http
    auth_step username,
              step2_authorization_header(username, password, nonce, auth_info),
              http
end

def parse_login_response response
    cookies = response.headers.get_fields("set-cookie") || []

    token = cookies.find { |i| i =~ /^sib-auth=/ }
    raise "Auth token cookie not found in response" if token.nil?

    device = cookies.find { |i| i =~ /^sib-deviceid=/ }
    raise "Device ID cookie not found in response" if device.nil?

    auth_cookies = HTTParty::CookieHash.new
    auth_cookies.add_cookies token
    auth_cookies.add_cookies device

    { auth_cookie: auth_cookies.to_cookie_string }
end

def login username, password, http
    nonce = generate_nonce

    # Step 1
    step = 1
    response = step1 username, nonce, http
    if response.code == 401
        auth_info = parse_auth_info response.headers["WWW-Authenticate"]

        # Step 2
        step = 2
        response = step2 username, password, nonce, auth_info, http
    end

    if response.code != 200
        raise "Auth step #{step}: network request failed with HTTP status #{response.code}"
    end

    parse_login_response response
end

def logout session, username, http
    encoded_username = encodeURI username
    response = http.post "https://online.roboform.com/rf-api/#{encoded_username}?logout", {}, {
        "Cookie" => session[:auth_cookie]
    }
end

#
# Tests
#

def check expression, message = ""
    raise message if !expression
end

def test_parse_auth_info config
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

def test_hash_password config
    hashed = hash_password config["password"], {
        salt: d64("A+Ft8UM674OZOOjUjXCdbw=="),
        iterations: 4096,
        md5?: false
    }

    check hashed == d64("b+rd7TUt65+hdE7+lHCBPPWHjxbq6qs0y7zufYfqHto=")
end

def test_compute_client_key config
    key = compute_client_key d64("b+rd7TUt65+hdE7+lHCBPPWHjxbq6qs0y7zufYfqHto=")

    check key == d64("8sbDhSTLwbl0FhiHAxFxGUQvQwcr4JIbpExO64+Jj8o=")
end

def test_compute_client_hash config
    hash = compute_client_hash d64("8sbDhSTLwbl0FhiHAxFxGUQvQwcr4JIbpExO64+Jj8o=")

    check hash == d64("RXO9q9pvaxlHnzGELfdRgzeb8G1KvG9/TkSPyFZK/G0=")
end

def test_step1_authorization_header config
    header = step1_authorization_header config["username"], "-DeHRrZjC8DZ_0e8RGsisg"

    check header == 'SibAuth realm="RoboForm Online Server",data="biwsbj1s' +
                    'YXN0cGFzcy5ydWJ5QGdtYWlsLmNvbSxyPS1EZUhSclpqQzhEWl8wZ' +
                    'ThSR3Npc2c="'
end

def test_step2_authorization_header config
    auth_info = {
        salt: d64("A+Ft8UM674OZOOjUjXCdbw=="),
        iterations: 4096,
        md5?: false,
        sid: "6Ag93Y02vihucO9IQl1fbg",
        nonce: "-DeHRrZjC8DZ_0e8RGsisgM2-tjgf-60m--FBhLQ26tg",
        data: "cj0tRGVIUnJaakM4RFpfMGU4UkdzaXNnTTItdGpnZi02MG0tLUZCaExRMjZ" +
              "0ZyxzPUErRnQ4VU02NzRPWk9PalVqWENkYnc9PSxpPTQwOTY="
    }

    header = step2_authorization_header config["username"],
                                        config["password"],
                                        "-DeHRrZjC8DZ_0e8RGsisg",
                                        auth_info

    check header == 'SibAuth sid="6Ag93Y02vihucO9IQl1fbg",data="Yz1iaXdzLH' +
                    'I9LURlSFJyWmpDOERaXzBlOFJHc2lzZ00yLXRqZ2YtNjBtLS1GQmh' +
                    'MUTI2dGcscD1VdGQvV3FCSm5SU2pyeTBRTCswa3owUCtDUk5rcXRC' +
                    'YytySHVmRHllaUhrPQ=="'
end

#
# main
#

config = YAML.load_file "config.yaml"
http = Http.new

# Poor man's tests
private_methods.grep(/^test_/).each do |i|
    send i, config
end

session = login config["username"], config["password"], http
logout session, config["username"], http
