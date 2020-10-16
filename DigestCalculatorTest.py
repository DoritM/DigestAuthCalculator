import unittest
from DigestCalc import DigestResponseCalculator


class CalcTestCase(unittest.TestCase):
    def test_response_value(self):
        print("########### Starting test #1: ###########\n\n")
        # Test the Wikipedia example from https://en.wikipedia.org/wiki/Digest_access_authentication
        authorization_header = r'Authorization: Digest username="Mufasa", realm="testrealm@host.com",' \
                               r'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", qop=auth,' \
                               r'nc=00000001,cnonce="0a4f113b",response="6629fae49393a05397450978507c4ef1", ' \
                               r'opaque="5ccc069c403ebaf9f0171e9517f40e41" '
        password = "Circle Of Life"
        method = "GET"

        calculator = DigestResponseCalculator(authorization_header, password, method)
        self.assertEqual(calculator.calculate_response(), "6629fae49393a05397450978507c4ef1")

        print("\n\n########### Starting test #2: ###########\n\n")
        authorization_header = r'Authorization: Digest username="a85g1i1ar7",realm="BroadWorks",nc=00000056,' \
                               r'nonce="BroadWorksXkg6xxmccTm5edzjBW",cnonce="BroadWorks",' \
                               r'uri="sip:voipproxy5.adpt-tech.com",qop=auth,algorithm=MD5,' \
                               r'response="4a6c95632786945c538cae87441648d7" '
        password = "&9^i%AFiS1@2"
        method = "REGISTER"

        calculator = DigestResponseCalculator(authorization_header, password, method)
        self.assertEqual(calculator.calculate_response(), "4a6c95632786945c538cae87441648d7")

        print("\n\n########### Starting test #3: ###########\n\n")
        authorization_header = r'Authorization: Digest username="hcd4u3fnrh",realm="BroadWorks",' \
                               r'nc=0000002f,nonce="BroadWorksXkg6xxmcbT8dhjg9BW",cnonce="BroadWorks",' \
                               r'uri="sip:voipproxy5.adpt-tech.com",qop=auth,algorithm=MD5,' \
                               r'response="b3f8eed671320a5564fd311240a56707" '
        password = "Qm$bI6rs^3po"
        method = "REGISTER"

        calculator = DigestResponseCalculator(authorization_header, password, method)
        self.assertEqual(calculator.calculate_response(), "b3f8eed671320a5564fd311240a56707")


if __name__ == '__main__':
    unittest.main()
