import unittest
import os
import ProcessCerts


class ConfigFileTests(unittest.TestCase):
    _config_file = os.getcwd() + "/testConfig.json"

    def setUp(self):
        with open(self._config_file, "w+") as f:
            print("{[\"domain\": \"incode.ca\","
                  "\"token\": \"jfgkhjk@3897yhgdf\","
                  "clientCertBase64: kghsdfewhfkfbwiufbidhbfe"
                  "]}", file=f)

    def tearDown(self):
        os.remove(self._config_file)

    def test_exists(self):
        self.assertTrue(ProcessCerts.check_config_exists(self._config_file))
        self.assertFalse(ProcessCerts.check_config_exists(os.getcwd() + "/DoesNotExist"))


class CSRValidationTests(unittest.TestCase):

    def test_csr_generation(self):
        return  # TODO: Finish this
        ProcessCerts.generate_csr(ProcessCerts.generate_key(), {})

    def test_key_generation(self):
        from ProcessCerts import generate_key
        from OpenSSL import crypto

        return  # TODO: Finish this

        count = [0, 0]
        self.assertAlmostEqual(bool(generate_key()), True)

        for bitSize in [(501, True), (-5, False), (None, False), (1024, True), (2048, True), (4096, True),
                        (8192, True), (126, True)]:
            for cryptoType in [(crypto.TYPE_RSA, True), (crypto.TYPE_DSA, True),
                               (None, False), (45, False)]:
                if bitSize[1] and cryptoType[1]:  # It should pass
                    self.assertAlmostEqual(bool(generate_key("", bits=bitSize[0], key_type=cryptoType[0])), True)
                elif not bitSize[1] and cryptoType[1]:  # The bitsize is wrong
                    if type(bitSize[0]) == int:  # The bitsize is a number, the value must be invalid
                        if bitSize[0] > 0:
                            with self.assertRaises(crypto.Error):
                                generate_key("", bits=bitSize[0], key_type=cryptoType[0])
                        else:
                            with self.assertRaises(ValueError):
                                print(bitSize[0])
                                generate_key("", bits=bitSize[0], key_type=cryptoType[0])
                    else:  # The bitsize is not a number, wrong type
                        with self.assertRaises(TypeError):
                            generate_key("", bits=bitSize[0], key_type=cryptoType[0])
                elif bitSize[1] and not cryptoType[1]:  # The crypto is wrong
                    if type(cryptoType[0]) != int:  # The crypto type is wrong
                        with self.assertRaises(TypeError):
                            generate_key("", bits=bitSize[0], key_type=cryptoType[0])
                    else:  # The crypto is an invalid enum int value
                        with self.assertRaises(crypto.Error):
                            generate_key("", bits=bitSize[0], key_type=cryptoType[0])
                count[1] += 1
            count[1] = 0
            count[0] += 1


class DomainValidationTests(unittest.TestCase):

    def test_validation(self):
        self.assertTrue(ProcessCerts.valid_domain("www.incode.ca"))
        self.assertTrue(ProcessCerts.valid_domain("www.inco-de.ca"))
        self.assertTrue(ProcessCerts.valid_domain("www.in-cod-e.ca"))
        self.assertTrue(ProcessCerts.valid_domain("in--code.ca"))
        self.assertFalse(ProcessCerts.valid_domain("-in--code.ca"))
        self.assertFalse(ProcessCerts.valid_domain("inc-ode-.ca"))
        self.assertFalse(ProcessCerts.valid_domain("inc5ode-.ca"))
        self.assertTrue(ProcessCerts.valid_domain("inc5ode.ca"))
        self.assertTrue(ProcessCerts.valid_domain("645.inc5ode.ca"))
        self.assertFalse(ProcessCerts.valid_domain("645.inc5ode."))
        self.assertFalse(ProcessCerts.valid_domain(".inc5ode.com"))
        self.assertTrue(ProcessCerts.valid_domain("e.com"))
        self.assertFalse(ProcessCerts.valid_domain(".com"))
        self.assertFalse(ProcessCerts.valid_domain("hello#ol#good%chap.co=m"))


if __name__ == '__main__':
    unittest.main()
