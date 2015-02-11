#!/usr/bin/env python
"""
This implements a logstash-forwarder compatible formatter and log handler.
"""
from __future__ import print_function
from backports.ssl_match_hostname import match_hostname, CertificateError
import struct
import logging
import errno
import socket
import sys
from logging.handlers import SocketHandler
from ssl import wrap_socket, CERT_REQUIRED, SSLError


class StashwardFormatter(logging.Formatter):
    def __init__(self, message_type="django"):
        self.host = socket.gethostname()
        self.message_type = message_type

    def get_extra_fields(self, record):
        """Tack on all the fields from the extra parameter on logging calls"""
        # The list contains all the attributes listed in
        # http://docs.python.org/library/logging.html#logrecord-attributes
        skip_list = (
            'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
            'funcName', 'id', 'levelname', 'levelno', 'lineno', 'module',
            'msecs', 'msecs', 'message', 'msg', 'name', 'pathname', 'process',
            'processName', 'relativeCreated', 'thread', 'threadName', 'extra')

        if sys.version_info < (3, 0):
            easy_types = (basestring, bool, dict, float, int, list, type(None))
        else:
            easy_types = (str, bool, dict, float, int, list, type(None))

        fields = {}

        for key, value in record.__dict__.items():
            if key not in skip_list:
                if isinstance(value, easy_types):
                    fields[key] = value
                else:
                    fields[key] = repr(value)

        return fields

    def get_debug_fields(self, record):
        """Format the exception info"""
        fields = {
            'exc_info': self.formatException(record.exc_info),
            'process': record.process,
        }

        # funcName was added in 2.5
        if not getattr(record, 'funcName', None):
            fields['funcName'] = record.funcName

        # processName was added in 2.6
        if not getattr(record, 'processName', None):
            fields['processName'] = record.processName

        return fields

    def format(self, record):
        """Create a dict from the logging record"""
        message = {
            '@version': 1,
            'message': record.getMessage(),

            # Extra Fields
            'levelname': record.levelname,
            'logger': record.name,
            'type': self.message_type,
            'path': record.pathname,

            # required for logstash forwarder to work
            'host': self.host,
            "line": record.lineno,
            "offset": 0, # this is completely meaningless, but required
        }

        # Add extra fields
        message.update(self.get_extra_fields(record))

        # If exception, add debug info
        if record.exc_info:
            message.update(self.get_debug_fields(record))

        return message


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
        self.send(struct.pack("!ssI", b"1", b"W", self.MAX_SEQUENCE_NUMBER))

    def makeSocket(self):
        """Make the socket and wrap it with SSL. A valid certificate is required from a trusted CA"""
        socket = SocketHandler.makeSocket(self)

        try:
            socket = wrap_socket(socket, cert_reqs=CERT_REQUIRED, ca_certs=self.ca_certs)
        except SSLError as e:
            # the ssl certificate was probably bad
            print("ERROR: " + self.__class__.__name__ + " says: " + str(e) + ". This is likely caused by a CN mismatch, or an invalid certificate file at %s" % self.ca_certs, file=sys.stderr)
        except OSError as e:
            # if we get an ENOENT, that's because the ca_file is bad
            if e.errno == errno.ENOENT:
                print("ERROR: " + self.__class__.__name__ + " says: %s" % str(e) + ". This error is probably caused by a bad CA file at %s" % self.ca_certs, file=sys.stderr)

        # some python versions do not do a CN match check, so we have to do it
        try:
            match_hostname(socket.getpeercert(), self.host)
        except CertificateError as e:
            print("ERROR: " + self.__class__.__name__ + " says: %s" % str(e), file=sys.stderr)
            socket.close()
            # raising an OSError will trigger createSocket to retry after a period of time
            raise OSError("CN Mismatch")

        return socket

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
        format_string = ["!ssII"]
        string = [b"1", b"D", sequence_number, len(data)]

        for key, value in data.items():
            # encode the keys and values as utf8
            key = str(key).encode("utf8")
            value = str(value).encode("utf8")

            # tack on the key length
            format_string.append("I")
            string.append(len(key))
            # tack on the key itself
            format_string.append(str(len(key)) + "s")
            string.append(key)
            # tack on the value length
            format_string.append("I")
            string.append(len(value))
            # tack on the value
            format_string.append(str(len(value)) + "s")
            string.append(value)

        return struct.pack("".join(format_string), *string)


if __name__ == "__main__":
    root = logging.getLogger('')
    root.setLevel(logging.INFO)
    handler = StashwardHandler("logs.rc.pdx.edu", 5043, ca_certs="/etc/pki/tls/certs/PSUCA.crt")
    root.addHandler(handler)
    logging.info("Foo")
    try:
        raise ValueError("foo")
    except ValueError:
        logging.exception("Foobar!")
