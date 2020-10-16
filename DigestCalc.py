# According to https://tools.ietf.org/html/rfc3261

# Authorization header looks like:
# Authorization: Digest username="bob", realm="biloxi.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
# uri="sip:bob@biloxi.com", qop=auth, nc=00000001, cnonce="0a4f113b", response="6629fae49393a05397450978507c4ef1",
# opaque="5ccc069c403ebaf9f0171e9517f40e41"

# Implementation according to https://en.wikipedia.org/wiki/Digest_access_authentication :

import re
import sys
import hashlib


class DigestResponseCalculator:
    def __init__(self, authorization_header, password, method):
        self.authorization_header = authorization_header
        self.password = password
        self.method = method

    def calculate_response(self):
        # First - find all the ", occurences in the string, and put spaces between them.
        # Then applying regex to extract values will be simpler.
        # authorization_header = re.sub(r'a', r',aaa', authorization_header)
        self.authorization_header = re.sub(r'",', r'" ,', self.authorization_header)
        print("authorization_header after normalizing = {}".format(self.authorization_header))

        # Extract the needed parameters' values from the authorization_header
        username = DigestResponseCalculator.apply_regex(self.authorization_header, r'.*username\s*=\s*"(\w+)"', "username")
        realm = DigestResponseCalculator.apply_regex(self.authorization_header, r'.*realm\s*=\s*"(\S+)"', "realm")
        nonce = DigestResponseCalculator.apply_regex(self.authorization_header, r'.*\Wnonce\s*=\s*"(\w+)"', "nonce")
        nonce_count = DigestResponseCalculator.apply_regex(self.authorization_header, r'.*nc\s*=\s*((\d|[a-f])+)', "nc")
        client_nonce = DigestResponseCalculator.apply_regex(self.authorization_header, r'.*cnonce\s*=\s*"(\w+)"', "cnonce")
        uri = DigestResponseCalculator.apply_regex(self.authorization_header, r'.*\Wuri\s*=\s*"(\S+)"', "uri")
        qop = DigestResponseCalculator.apply_regex(self.authorization_header, r'.*\Wqop\s*=\s*([a-zA-Z-]+)', "qop")
        algorithm = DigestResponseCalculator.apply_regex(self.authorization_header, r'.*algorithm\s*=\s*(\w+)', "algorithm", False)

        print("Regex results:\n  username = {},\n  realm = {},\n  nonce = {},\n  nonce_count = {},\n  "
              "client_nonce = {},\n  uri = {},\n  qop = {},\n  algorithm = {}\n".
              format(username, realm, nonce, nonce_count, client_nonce, uri, qop, algorithm))

        ha1 = self.__calculate_ha1_value(algorithm, username, realm)
        ha2 = self.__calculate_ha2_value(qop, uri)
        response = DigestResponseCalculator.__calculate_response_param_value(ha1,
                                                                             ha2,
                                                                             qop,
                                                                             nonce,
                                                                             nonce_count,
                                                                             client_nonce)
        print("Calculated Results:\n  ha1 = {}\n  h2 = {}\n  response = {}\n".format(ha1, ha2, response))
        return response

    def __calculate_ha1_value(self, algorithm, username, realm):
        # If the algorithm directive's value is "MD5" or unspecified, then HA1 is
        #   HA1 = MD5(username:realm:password)
        # If the algorithm directive's value is "MD5-sess", then HA1 is
        #   HA1 = MD5(MD5(username:realm:password):nonce:cnonce)

        # check if md5 or empty, meaning algorithm param was missing -> then default is md5
        ha1 = ""
        if algorithm.lower() == "md5" or not algorithm:
            concatenated_val = username + ':' + realm + ':' + self.password
            hash_val = hashlib.md5(concatenated_val.encode())
            ha1 = hash_val.hexdigest()
        else:
            print("Error: not supported hash function {}".format(algorithm))
            sys.exit()
        return ha1

    def __calculate_ha2_value(self, qop, uri):
        # If the qop directive's value is "auth" or is unspecified, then HA2 is
        #    HA2 = MD5(method:digestURI)
        # If the qop directive's value is "auth-int", then HA2 is
        #    HA2 = MD5(method:digestURI:MD5(entityBody))
        ha2 = ""
        lower_case_qop = qop.lower()
        if lower_case_qop == "auth":
            concatenated_val = self.method + ':' + uri
            hash_val = hashlib.md5(concatenated_val.encode())
            ha2 = hash_val.hexdigest()
        elif lower_case_qop == "auth-int":
            print("Error: qop \"auth-int\" is not supported right now")
            sys.exit()
        else:
            print("Error: Unsupported qop value {}. Exit program".format(qop))
            sys.exit()
        return ha2

    @staticmethod
    def __calculate_response_param_value(ha1, ha2, qop, nonce, nonce_count, client_nonce):
        # If the qop directive's value is "auth" or "auth-int", then compute the response as follows:
        #    response = MD5(HA1:nonce:nonceCount:cnonce:qop:HA2)
        # If the qop directive is unspecified, then compute the response as follows:
        #   response = MD5(HA1:nonce:HA2)
        lower_case_qop = qop.lower()
        if lower_case_qop == "auth" or lower_case_qop == "auth-int":
            concatenated_val = ha1 + ':' + nonce + ':' + nonce_count + ':' \
                               + client_nonce + ':' + qop + ':' + ha2
        else:
            concatenated_val = ha1 + nonce + ha2
        hash_val = hashlib.md5(concatenated_val.encode())
        response = hash_val.hexdigest()
        return response

    @staticmethod
    def apply_regex(input_str, regex_str, searched_element, is_element_mandatory=True):
        search_obj = re.search(regex_str, input_str, re.S | re.I)
        if not search_obj:
            print("No \"{}\" in input_str <{}>".format(searched_element, input_str))
            if is_element_mandatory:
                print("Element {} is mandatory. Exit".format(searched_element))
                sys.exit()
            else:
                return ""

        return search_obj.group(1)


if __name__ == '__main__':
    password_in = input("Type credentials password:")
    authorization_header_in = input("Type Authorization:")
    method_in = input("Type Method:")
    calculator = DigestResponseCalculator(authorization_header_in, password_in, method_in)
    calculator.calculate_response()
