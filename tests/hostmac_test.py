import unittest
import sys
sys.path.append('..')
import hostmac


class HostMAC_Tests(unittest.TestCase):

    # create_output_folder_name()
    def test_create_output_folder_name_output_type(self):
        self.assertEqual(str, type(hostmac.create_output_folder_name()))

    def test_create_output_folder_fail_on_wrong_arguments(self):
        self.assertRaises(TypeError, hostmac.create_output_folder_name, "foo")

    # create_csv_file_name()
    def test_create_csv_file_name_output_type(self):
        self.assertEqual(str, type(hostmac.create_csv_file_name()))

    def test_create_csv_file_name_fail_on_wrong_arguments(self):
        self.assertRaises(TypeError, hostmac.create_csv_file_name, "foo")

    # detect_os()
    def test_detect_os_returns_dict(self):
        self.assertEqual(dict, type(hostmac.detected_os))

    # subproc_pipe_runner()
    def test_subproc_pipe_runner_returns_tuple(self):
        self.assertEqual(tuple, type(hostmac.subproc_pipe_runner(
            "192.168.1.1", "ping -c 1 192.168.1.1")))

    # ip_check()
    def test_ip_check_returns_bool(self):
        self.assertEqual(bool, type(hostmac.ip_check("192.168.1.1")))

    def test_ip_check_valid_ip_is_true(self):
        self.assertTrue(hostmac.ip_check("192.168.1.1"))

    def test_ip_check_invalid_ip_is_false(self):
        self.assertFalse(hostmac.ip_check("foo"))
        self.assertFalse(hostmac.ip_check("192.168.1.256"))

    def test_ip_check_fail_on_wrong_argument(self):
        self.assertRaises(TypeError, hostmac.ip_check, 9)
        self.assertRaises(TypeError, hostmac.ip_check, [9, 10])
        self.assertRaises(TypeError, hostmac.ip_check, False)

    # nslooky()
    def test_nslooky_returns_string(self):
        self.assertEqual(str, type(hostmac.nslooky(
            "192.168.1.1", detected_os=hostmac.detect_os())))

    def test_nslooky_fails_on_wrong_argument(self):
        self.assertRaises(TypeError, hostmac.nslooky(
            100, detected_os=hostmac.detect_os()))

    # get_ping_ms_response()
    def test_get_ping_ms_response_returns_string(self):
        self.assertEqual(str, type(hostmac.get_ping_ms_response(
            "192.168.1.1", detected_os=hostmac.detect_os())))

    # get_mac()
    def test_get_mac_returns_string(self):
        self.assertEqual(str, type(hostmac.get_mac(
            "192.168.1.1", detected_os=hostmac.detect_os())))

    # detect_ip()
    def test_detect_ip_returns_string(self):
        self.assertEqual(str, type(hostmac.detect_ip("192.168.1.1")))

if __name__ == '__main__':
    unittest.main()
