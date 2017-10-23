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
    response = http.post "https://online.roboform.com/rf-api/#{encoded_username}?logout", {}, {
        "Cookie" => session[:auth_cookie]
    }
end

def get_user_data session, username, http
    encoded_username = encodeURI username
    response = http.get "https://online.roboform.com/rf-api/#{encoded_username}/user-data.rfo?_1337", {
        "Cookie" => session[:auth_cookie]
    }
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

def test_parse_onefile config
    blob = d64 "b25lZmlsZTEHAU8FAABVlI9vpN8EKVpPnquRJrSYZ3NlbmNzdDEAAgAQAA" +
               "AQlTM1snvUW6/VmXbjKu7l65tWu0R6/8YOu5yjBUMB24uwfGNA/EmFJuUz" +
               "iYToeTliRlpgV6+CVfm7nJ/mwTmrHxPbkhrjLHQ+AAOeNSeEFyvxd8ntOl" +
               "v5jCjsifPdMg/AjZbapv0PLB0z2/LOoM37SbN9JK/aF3JjYJwNsN8oEskA" +
               "92B7qsmkawx55X5ixFc5rvcLjzL2qPkgzHxwftX1OPM6bJVQRTHQKXa7t9" +
               "nqugLXI/ij24tGkTdbGmaOFg1nVO0+X0OubqqF41K8uO5ePSrA+e/OXvr6" +
               "6hvvf2q168/uKNel74j20H5xJpZhY6VsgmQs3OSquOp2zJ7/TMJCnkgMuD" +
               "mqWwY4O5KIloaoK3qMLdbKiyjmsg3QCsOBxIRw2QTWeuyhJSTcFDgauima" +
               "oKNYxNUfi8K18/R9WBt+rLmP7v8ZKmKu2QGKbAwO05zhvXhq5VOau7R9CD" +
               "KNVexeGbb86+cyxIcM0uf2ds9nLLMZPHUj5kYvj+frtMUQq2ToOsbEPdeG" +
               "68tG1f4yosEkifseXfWrWzMrAGeOfh2Q1yLFCzv7ATqjAsooWR1nfk5air" +
               "xf3nDqToPllb+C6DVHqvp8UadZXnhdj5kxvfd0BqOSu/lZFsGaJFxrGSzG" +
               "ZTx6kxZrUUnVLOoPfNJwmcADGI0hRXbZdbmxaXHnMuRtqOXspxKsgu2H6D" +
               "sIoJwgntGazg99oBvkf90Mf8fjCKLIiBwbcqimiR+knKhCuijE6QUvCXqV" +
               "INHj7dBKT83jGj/rgJ/GtfpKo/Rmm6EUoEJmKZ7YSqaNlPkW1NKaQxu56M" +
               "DWQX2Ioc3hZU6S4oPbxyXm1vy9UxhgSFctg9pSeXa+BDUTuxhRE1HZ6f0g" +
               "lUz1sWVyE8WOToWndlRWDEM+G6+RYHlmADAq67NYLxssYC3Enej300qxY1" +
               "pAxKlWF4MPTH+ued9IHNjTgA5bJhSRimrBEGFrESICVii3RKljDnviib1Q" +
               "K+74vaK47Jd+jGn+8cunD7lSnilTms1u/7uqgbhXzf9426pe92WoHFpmqb" +
               "I6FvLSvycl9oEzaVnayoGntJ2A5UJ6uROw2srChfx64uabVy0yxkU+86zH" +
               "VuN/QJcWKSmQmR7HHrWutOizDed1+uXgj8AGb7XQiiDgpGRt4TE/WSsvjv" +
               "6CCy+CI/xpiYrkmyezY+2OLF8v/PAW1qbwn/2ZKnRwJ3YI2DFr438CLO1O" +
               "7xqEp0RC0+8GBlGWwZ9BfWNvE94+/QIP3pV+vojlaXPt8GeOlesCSfpFXs" +
               "8gQmSdOoriRhxW98zGyZugwM27E/epOGKyghYfShIqVtYGtLKiF5kbvNXs" +
               "NaiB5WgPzg/5ygh26IgsdT8U8+0cdEbmZQdhRGEsNdIOjFExZRkWlAllgS" +
               "HfFyj0YL6U6DGlhDY9iLFjlJQlrCzo05MoatNMRt82VLfIys47YluU9wZO" +
               "x/7QdcKd6czz4te4SAFGDmvCL5HVuAV+sPHQG5azADUGMO8g/a+ImJic+U" +
               "/5rHTvDYMaveuWBHLi5LY7SlTnq6qju4qZXdiX8oh8xWND6DCCyg9zH7rQ" +
               "r5c3m8z6Bq8z/9cG2cpWUXJlG+gdp3H1DFIgxmnEu8nzyVfxx0fg+TpTJy" +
               "eMVrbH7rZ8f7uSkzKMVLSxIfnuk1yNHDsOrTpG76zXnHVil+hNczDw9MFO" +
               "IhH7LnWjSzGX4klWJnGtWQcV2vB3qtoPvRgo24L4dUpT+6XsYJLcWdOIe0" +
               "dRXjXomQAUTZoDmTN31Pew+nlwBrzzFgB7C5KMG9lPKlClEbXbMaFSAAAA" +
               "AA=="
    json = parse_onefile blob, config["password"]

    check Hash === json
    check json.keys == %w{i c}
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

exit

username = config["username"]
session = login username, config["password"], http
user_data = get_user_data session, username, http
logout session, username, http
