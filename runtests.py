#!/usr/bin/env python
import logging
import os
import socket
import sys
import tempfile
import time
try:
    import unittest2 as unittest
except ImportError:
    import unittest
from ssl import wrap_socket
from multiprocessing import Process
from stashward import StashwardHandler
from stashward.handler import ErrorCode


class FullTest(unittest.TestCase):
    """
    This test creates a listening SSL socket on an abitrary port and waits for
    connections on another process. We then setup the log handler that connects
    on that socket, and send logging messages to it.
    """

    def setUp(self):
        super(FullTest, self).setUp()
        # create the socket, and bind to an abitrary port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s = wrap_socket(s, keyfile="certs/localhost.key", certfile="certs/localhost.crt", server_side=True)
        s.bind(("localhost", 0))
        s.listen(1)
        self.port = s.getsockname()[1]

        def ensure_messages_are_correct(socket):
            """
            Wait for the client to connect, and then ensure the messages
            received and are correct
            """
            # wait until someone connects...
            client, address = socket.accept()
            # the first message should be the window size, that starts with 1D, and
            # ends with 2**32-1 in big endian format
            assert(client.read() == b'1W\xff\xff\xff\xff')
            # the second message should start with the 1D packet header, the
            # sequence number (0), and the number of key/value pairs, which is
            # 9 (@version, message, levelname, logger, etc)
            assert(client.read()[:10] == b'1D\x00\x00\x00\x00\x00\x00\x00\x09')
            # the third message should contain strack trace information
            assert(b"Traceback" in client.read())
            s.close()

        # start the listening process
        Process(target=ensure_messages_are_correct, args=[s]).start()

    def test(self):
        """
        Ensure the logger gets the 3 messages: One for the window size, and two
        data packets
        """
        root = logging.getLogger('')
        root.setLevel(logging.INFO)
        handler = StashwardHandler("localhost", self.port, ca_certs="certs/localhost.crt")
        root.addHandler(handler)
        logging.info("Foo")
        try:
            raise ValueError("foo")
        except ValueError:
            logging.exception("Foobar!")
        handler.close()


class TestHandler(unittest.TestCase):
    def test_makePickle(self):
        """Ensure the sequence number rolls over"""
        handler = StashwardHandler("google.com", 443, ca_certs="certs/ca-bundle.crt")
        handler.sequence_number = 2**32-1

        # mock up a log record
        class Record(dict):
            def getMessage(self):
                return ''

            def __getattr__(self, key):
                return ''

        handler.makePickle(Record())
        self.assertEqual(handler.sequence_number, 0)
        handler.close()

    def test_packetize(self):
        """Ensure the generated packet follows the right protocol"""
        handler = StashwardHandler("google.com", 443, ca_certs="certs/ca-bundle.crt")
        # ensure these get converted to a packet with string keys and string values
        d = {"foo": "bar", 4: 4}
        arbitrary_sequence_number = 2503748420
        packet = handler.packetize(d, arbitrary_sequence_number)
        # we'll get a different looking package depending on the order of the dict
        if list(d.keys())[0] == "foo":
            self.assertEqual(packet, b'1D\x95\x3c\x2b\x44\x00\x00\x00\x02\x00\x00\x00\x03foo\x00\x00\x00\x03bar\x00\x00\x00\x014\x00\x00\x00\x014')
        else:
            self.assertEqual(packet, b'1D\x95\x3c\x2b\x44\x00\x00\x00\x02\x00\x00\x00\x014\x00\x00\x00\x014\x00\x00\x00\x03foo\x00\x00\x00\x03bar')
        handler.close()

    def test_unicode(self):
        """This is a regression test for handling unicode in Python2"""
        handler = StashwardHandler("google.com", 443, ca_certs="certs/ca-bundle.crt")
        # the unicode codepoint 044f (in hex) (or 1103 in decimal) is a
        # backwards looking R character. The UTF8 encoding of this particular
        # character is 0xD18F
        d = {u"\u044f": u"\u044f"}
        arbitrary_sequence_number = 5
        packet = handler.packetize(d, arbitrary_sequence_number)
        self.assertEqual(packet, b'1D\x00\x00\x00\x05\x00\x00\x00\x01\x00\x00\x00\x02\xd1\x8f\x00\x00\x00\x02\xd1\x8f')
        handler.close()


class TestSSL(unittest.TestCase):
    def setUp(self):
        super(TestSSL, self).setUp()
        self.stderr = tempfile.TemporaryFile("w+")

    def tearDown(self):
        self.stderr.close()
        super(TestSSL, self).tearDown()

    def test_ca_file_not_found(self):
        """
        Ensure a helpful error is printed to stderr if the ca file is not
        found, and the socket doesn't get created.
        """
        with RedirectStdStreams(stderr=self.stderr):
            handler = StashwardHandler("google.com", 443, ca_certs=".file_that_does_not_exist")
        self.stderr.seek(0)
        content = self.stderr.read()
        # Python3 gives better error messages
        if sys.version_info[0] >= 3:
            self.assertIn("ERROR %d:" % ErrorCode.FILE_NOT_FOUND, content)
            self.assertIn("FileNotFoundError", content)
        else:
            self.assertIn("ERROR %d:" % ErrorCode.GENERIC_SSL_FAILURE, content)
        # ensure the socket didn't get created somehow
        self.assertFalse(handler.sock)
        handler.close()

    def test_ca_file_is_invalid(self):
        """
        Ensure a helpful error is printed to stderr if the ca file is invalid
        and the socket doesn't get created
        """
        with RedirectStdStreams(stderr=self.stderr):
            # server.key is not not a valid CA file
            handler = StashwardHandler("google.com", 443, ca_certs="certs/localhost.key")
        self.stderr.seek(0)
        content = self.stderr.read()
        self.assertIn("ERROR %d:" % ErrorCode.GENERIC_SSL_FAILURE, content)
        # ensure the socket didn't get created somehow
        self.assertFalse(handler.sock)
        handler.close()

    def test_not_a_trusted_cert(self):
        """
        Ensure a helpful error is printed to stderr if the certificate is not
        trusted and the socket doesn't get created
        """
        with RedirectStdStreams(stderr=self.stderr):
            # Google isn't trusted by server.crt
            handler = StashwardHandler("google.com", 443, ca_certs="certs/localhost.crt")
        self.stderr.seek(0)
        content = self.stderr.read()
        self.assertIn("ERROR %d:" % ErrorCode.GENERIC_SSL_FAILURE, content)
        # check for the better error message in Python 3
        if sys.version_info[0] >= 3:
            self.assertIn("CERTIFICATE_VERIFY_FAILED", content)
        # ensure the socket didn't get created somehow
        self.assertFalse(handler.sock)
        handler.close()

    def test_cn_mismatch(self):
        """
        Ensure a helpful error is printed to stderr if the certificate is
        trusted by the CN is a mismatch and the socket doesn't get created
        """
        google_ip = socket.gethostbyname('google.com')
        with RedirectStdStreams(stderr=self.stderr):
            # The certificate for google isn't issued for the IP address
            handler = StashwardHandler(google_ip, 443, ca_certs="certs/ca-bundle.crt")
        self.stderr.seek(0)
        content = self.stderr.read()
        self.assertIn("ERROR %d:" % ErrorCode.CN_MISMATCH, content)
        # ensure the socket didn't get created somehow
        self.assertFalse(handler.sock)
        handler.close()


# Thanks http://stackoverflow.com/a/6796752/2733517
class RedirectStdStreams(object):
    def __init__(self, stdout=None, stderr=None):
        self._stdout = stdout or sys.stdout
        self._stderr = stderr or sys.stderr

    def __enter__(self):
        self.old_stdout, self.old_stderr = sys.stdout, sys.stderr
        self.old_stdout.flush(); self.old_stderr.flush()
        sys.stdout, sys.stderr = self._stdout, self._stderr

    def __exit__(self, exc_type, exc_value, traceback):
        self._stdout.flush(); self._stderr.flush()
        sys.stdout = self.old_stdout
        sys.stderr = self.old_stderr


if __name__ == '__main__':
    unittest.main()
