from __future__ import unicode_literals
from __future__ import print_function

import traceback
import struct
import logging
import errno
import socket
import sys
import six

from logging.handlers import SocketHandler
from ssl import wrap_socket, CERT_REQUIRED, SSLError

try:
    from ssl import match_hostname, CertificateError
except ImportError:
    from backports.ssl_match_hostname import match_hostname, CertificateError
from .formatter import StashwardFormatter


class ErrorCode:
    """
    We use some random numbers for error codes to make unit testing a little
    easier, and for greppability
    """
    GENERIC_SSL_FAILURE = 42218
    CN_MISMATCH = 34624
    FILE_NOT_FOUND = 17253

class StashwardHandler(SocketHandler):
    # The sequence number is 32 bits, so it should rollover to 0 when it gets there
    MAX_SEQUENCE_NUMBER = 2**32-1

    def __init__(self, host, port, ca_certs, message_type="django"):
        """
        Specify the host, port, and file path to the concatenated list of CAs
        """
        SocketHandler.__init__(self, host, port)
        self.formatter = StashwardFormatter(message_type)
        self.ca_certs = ca_certs
        self.sequence_number = 0

        # immediately send a packet setting the windows size to something huge
        # since we don't care about ACKs
        self.send(struct.pack(b"!ssI", b"1", b"W", self.MAX_SEQUENCE_NUMBER))

    def makeSocket(self):
        """Make the socket and wrap it with SSL. A valid certificate is required from a trusted CA"""
        s = SocketHandler.makeSocket(self)

        try:
            s = wrap_socket(s, cert_reqs=CERT_REQUIRED, ca_certs=self.ca_certs)
        except SSLError as e:
            # the ssl certificate was probably bad
            # since logging doesn't work, print to stderr
            traceback.print_exc()
            print("ERROR %d: This is likely caused by a CN mismatch, an invalid certificate file at %s, or a verification failure based on your CA file" % (ErrorCode.GENERIC_SSL_FAILURE, self.ca_certs), file=sys.stderr)
            s.close()
            raise
        except OSError as e:
            s.close()
            # if we get an ENOENT, that's because the ca_file is bad
            if e.errno == errno.ENOENT:
                traceback.print_exc()
                print("ERROR %d: This error is probably caused by a bad CA file at %s" % (ErrorCode.FILE_NOT_FOUND, self.ca_certs), file=sys.stderr)
            s.close()
            raise

        # some python versions do not do a CN match check, so we have to do it
        try:
            match_hostname(s.getpeercert(), self.host)
        except CertificateError as e:
            traceback.print_exc()
            print("ERROR %d: The CN provided by the server didn't match the host you connected to" % ErrorCode.CN_MISMATCH, file=sys.stderr)
            s.close()
            # raising a socket error will trigger createSocket to retry after a period of time
            raise socket.error("CN Mismatch")

        return s

    def makePickle(self, record):
        """Format the record, and turn it into a logstash compatible packet"""
        packet = self.packetize(self.formatter.format(record), self.sequence_number)
        # critical section here for incremeting the sequence_number. Notice, we
        # don't have to wrap a lock around this, because the base
        # logging.Handler will acquire a lock before calling emit(), which
        # calls this method
        self.sequence_number = self.sequence_number + 1 if self.sequence_number < self.MAX_SEQUENCE_NUMBER else 0
        return packet

    def packetize(self, data, sequence_number):
        """
        Turn a dict into a byte stream that is compatible with logstash-forwarder's protocol

        The packet looks like this:

        Header "1D" - the version and frame type (data) in ascii
        32 bit unsigned, big-endian, integer sequence number
        32 bit unsigned, big-endian, integer count of the number of (key, value) pairs
        For each key, value pair:
            32 bit unsigned, big-endian, integer number for the key length
            the key (raw bytes)
            32 bit unsigned, big-endian, integer number for the value length
            the value (raw bytes)


        The data *MUST* include a key/value pair for "host", "line" and
        "offset". That fact isn't documented anywhere but here. You're welcome.
        """
        format_string = [b"!ssII"]
        string = [b"1", b"D", sequence_number, len(data)]

        for key, value in data.items():
            # encode the keys and values as utf8-encoded bytestrings
            key = six.text_type(key).encode('utf-8')
            value = six.text_type(value).encode('utf-8')

            # tack on the key length
            format_string.append(b"I")
            string.append(len(key))
            # tack on the key itself
            format_string.append(six.text_type("%ds" % (len(key))).encode('utf-8'))
            string.append(key)
            # tack on the value length
            format_string.append(b"I")
            string.append(len(value))
            # tack on the value
            format_string.append(six.text_type("%ds" % (len(value))).encode('utf-8'))
            string.append(value)

        return struct.pack(b"".join(format_string), *string)
