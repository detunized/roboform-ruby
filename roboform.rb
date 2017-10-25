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

class StringIO
    def read_format size, format
        read(size).unpack(format)[0]
    end
end

class Integer
    def bit_set? index
        (self & (1 << index)) != 0
    end
end

#
# Crypto
#

def hmac key, message
    OpenSSL::HMAC.digest "sha256", key, message
end

def decrypt_aes ciphertext, key, iv, padding = nil
    c = OpenSSL::Cipher.new "aes-256-cbc"
    c.decrypt
    c.key = key
    c.iv = iv
    c.padding = padding if padding
    c.update(ciphertext) + c.final
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
    http.post "https://online.roboform.com/rf-api/#{encoded_username}?logout", {}, {
        "Cookie" => session[:auth_cookie]
    }
end

def get_user_data session, username, http
    encoded_username = encodeURI username
    response = http.get "https://online.roboform.com/rf-api/#{encoded_username}/user-data.rfo?_1337", {
        "Cookie" => session[:auth_cookie]
    }

    response.parsed_response
end

#
# Blob parser
#

def parse_onefile blob, password
    StringIO.open blob do |io|
        magic = io.read 8
        raise "Invalid signature '#{magic}'" if magic != "onefile1"

        flags = io.readbyte

        has_checksum = flags.bit_set? 0
        encrypted = flags.bit_set? 1
        compressed = flags.bit_set? 2

        if has_checksum
            c = io.readbyte
            raise "Checksum type #{c} is not supported" if c != 1
        end

        content_length = io.read_format 4, "V"
        stored_checksum = io.read 16
        content = io.read content_length

        actual_checksum = Digest::MD5.digest content
        raise "Invalid checksum" if actual_checksum != stored_checksum

        raw = decrypt_content content,
                             {encrypted: encrypted, compressed: compressed},
                             password

        JSON.load raw
    end
end

def decrypt_content content, options, password
    StringIO.open content do |io|
        magic = io.read 8
        raise "Invalid signature '#{magic}'" if magic != "gsencst1"

        reserved_size = io.readbyte

        kdf_algorithm = io.readbyte
        kdf_hash = ""
        case kdf_algorithm
        when 0, 1
            raise "SHA-1 KDF is not supported"
        when 2
            kdf_hash = "sha256"
        when 3, 4
            kdf_hash = "sha512"
        else
            raise "KDF algorithm #{kdf_algorithm} is not supported"
        end

        iterations = io.read_format 4, "V"
        salt_size = io.readbyte
        salt = io.read salt_size
        reserved = io.read reserved_size

        padding = if reserved.size > 0 && reserved[0].ord.bit_set?(0)
            0 # No padding
        else
            nil # OpenSSL defults to PKCS7 padding
        end

        key_iv = OpenSSL::PKCS5.pbkdf2_hmac password, salt, iterations, 64, kdf_hash
        key = key_iv[0, 32]
        iv = key_iv[32, 16]

        ciphertext = io.read
        plaintext = decrypt_aes ciphertext, key, iv, padding

        # Skip garbage
        xor = 0xaa
        start = 0
        plaintext.bytes.each do |i|
            start += 1
            xor ^= i
            break if xor == 0
        end

        Zlib::Inflate.new(Zlib::MAX_WBITS + 16).inflate plaintext[start..-1]
    end
end

def parse_accounts json
    traverse_parse get_root json
end

def get_root json
    children = json["c"] || []
    root = children[1] || {}

    info = root["i"] || {}
    raise "Root folder not found" if !info["F"] || info["n"] != "root"

    root
end

def traverse_parse root
    accounts = []
    traverse_folder root["c"] || [], "", accounts

    accounts
end

def traverse_folder entries, path, accounts
    entries.each do |entry|
        info = entry["i"] || {}
        name = info["n"] || ""
        if info["F"]
            traverse_folder entry["c"] || [],
                            path.empty? ? name : "#{path}/#{name}",
                            accounts
        else
            accounts << parse_account(entry["b"] || "{}", info["n"] || "", path)
        end
    end
end


def parse_account data, name, path
    json = JSON.load data

    {
        name: name,
        path: path,
        url: json["g"] || json["m"] || "",
        fields: parse_fields(json["f"] || [])
    }
end

def parse_fields fields
    fields
        .select { |i| (1..2) === i["t"] } # Only keep text (1) and password (2) inputs
        .reject { |i| i["d"] }            # Don't need input fields with default values
        .map { |i| {name: i["n"] || "", value: i["v"] || ""} }
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

def test_parse_accouts config
    blob = d64 "b25lZmlsZTEHAY8GAACVds6Fe4wEu/T0DayGA/TwZ3NlbmNzdDEAAgAQAA" +
               "AQmalFVuiCSwJ0PCCBxMZejzSjUl0mYQLyH6komWcc/2M2CS35wBIhatR7" +
               "uI1a3+NMCvLWbFcwWY0c/1+DuUs/b8zfndMot12m9MgNijzSQfRYbL9XjH" +
               "tIBOB66xMd4ep0bmnMlRx6rt7IPuvVIOVDB25x8vVzXJI7NaCVH/mcK5L/" +
               "6+4Qokfo9DscH8NJv6FgxfUP7OS4U7D8HkshX7fqwWAmbMtCH42RbqS3nu" +
               "4MM0PhIVybifOIr/wiBQaQg08lhZ5Q0mu1D0thdOL6FchljR3nWRgWmEde" +
               "c39YBTYdaJeq6489WY2hewq/6WiALwP8w9ANDs4qSOd+pCPPx2GnRVLoCt" +
               "A6e9Q1/iqOH+lA7u77sKLY3zkNQ1+apxhWKPvTy2hIr3Y+ZzLmr2gSMeHv" +
               "NZJ87s9ePCtouesV/obvBfApxP8YXf28Dmegswd0GFQmC94M9EDLXUu6fG" +
               "HNDCKEo49ht+6+6hEIV+ntE5pb4yaS4SKOKzUsLMl8UVUXCEPl1YOyaBxI" +
               "iP/niGn5t0V49naJ/oClB/eLoiVa3ywSCTh8VgrxhEqFoIERr+yGr2hpNM" +
               "zUebFdHZo/RW4cqi70QxmoJ1udAfn3trFVeH9ZtqV3QTCb6UOAoEJQLSIA" +
               "ElcuwblpEz3pVaQ5eBdBQNSviEj2BphHbW4POklw1ePoxqQwNqE7VpIwJ9" +
               "v3sU20QvTlxlQ6IRdZa4WkBMZ9hfAPNFU1OwhZfylR+cDIKxH5wSuS8oEi" +
               "NZS7wK9i6xElA0syueih1H/Lu8dFA4Kov1rzzEq4fnIVl84BtAiJZnOg/9" +
               "KzDXiwm2gvYvvFrA00DEdnW/uhC84ELD5UY+p19VXdWjyVWdaaml0ISWTd" +
               "QGK4TAPZdghFGnfxZGJWmE3UEHrhW/VePMWQb1+BJqWqLwsapBThVdX+rx" +
               "Ol8E3jo7bLbCPh3NtvNpgudy1s30ggQCEDFn1ra5PI3IfLVxgWVVNu1z5B" +
               "of36yUC9TeXCIi5wm7a9y+g0ZXUYMDUN9UX8NxUG1bSq+4jSi+0LcVgF8h" +
               "cmY918LeY/0miPV9JUmifItq1rUY3gi3naL99yOf534lKA3FibutuFxJ9+" +
               "dUBPYq6Atxi/irTPfkzAr2IyFQy9JzoXXn0qflpTWIZpa6fM8R39UVzSlt" +
               "FVcfKSsbEfFkINgBUJ3nRNoc+LDBi4/t5i0SY/QLUUE0VyS9ffHwlK/A10" +
               "ceXELIg6phnU7HnDv86dlsm2Ey19A49QWSjtxP4vMHZhGnGhyvOpuHmt8V" +
               "ogcgDf/JY+9SK8dQRjIijlvMqT28HUehJiOgnBENGeDmoV4g+noj3ibajp" +
               "zMeVxfpkd9BOYer0vPMmPjBqZFFXYeGlL8k91fGaX6MEWTbFUKjupJ7JhB" +
               "DX1lTfc6wTK5f9l8biAMZSUvqrDQ/EYpsoy4nAmCgwT7NxMbslAqY8eEWl" +
               "3S9BIOIrOBRI2HPcWMEBVBZ25nub2mNrIjdheksdr7xm1/Zk7oa35CnDnv" +
               "0EKC0/LV3OWSi48P2AQ96dsF+yx5wEJ9Kb5WuOvMwl31mQIwOhl35bA1um" +
               "I6+PRf9Y6J4cfNc34olCc+8SUZMNckPWsPSM/ULpGQ1tpCicKkJBaFBWjx" +
               "RDUuKxvANgxXgWUohyrx7X5YeXY3Y5HEY+edQCjudk6qE/gV8SCTlMwj0I" +
               "8OXz/1okRHvZPL+86mVj5YS5rzGLTnnPn4eSEnMSQ11HRlfh5Pmp5uz/ts" +
               "lsm+aF5B1zOJx/ryP0Uy8a5D7Dqb5juThCpDrJDxOO4SNTMSVO7jOBueit" +
               "UvmOHaBBRHYVhItRm2BkQojDq5o+h+RVeopvcbm+cUWrwN4paja04hUe/A" +
               "AkQ3l+71RnUy7rgozMNPQEsdZRabAQafMwKTaKS9mjP7msKTd/HHjuzd8L" +
               "W6Mf3HuECAGIjW9GVy3MkTrSRF4O5dq3e9tTQ2Yuuv3M5TAJkjKtdhoztl" +
               "91cJ4WjxDDYrq6sp07doR7yRi4dRymOZcFNtLEJNPESe3hiHXx7197FNtS" +
               "W9DLyBq0Wnsmz01fS4Z+7/uGuLG8TMRfzpcwlim+R0sbqyrWGQNfIAwd11" +
               "ngfqvYNBx6Jh7VtcZjmLdNCiM2nEAWsuvRv0RwjnZkA29iaJs/2x81cUke" +
               "mPJk94oh+PKK5BQ1XhfzDbqhMk8FiO7NU6SRZqE48MCPNRkEhZjssSGGS4" +
               "zpb4tKkJG+ZgJwXnEAAAA"
    json = parse_onefile blob, config["password"]

    check Hash === json
    check json.keys == %w{i c}

    accounts = parse_accounts json

    check accounts.size == 4
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

username = config["username"]
session = login username, config["password"], http
user_data = get_user_data session, username, http
logout session, username, http

accounts = parse_accounts parse_onefile user_data, config["password"]

accounts.each_with_index do |i, index|
    puts "#{index + 1}: #{i[:name]}, #{i[:url]}, #{i[:path]} #{i[:fields]}"
end
