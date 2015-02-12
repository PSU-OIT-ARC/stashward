import logging
import socket
import sys


# Code shameless taken from Vladimir Klochan
# https://github.com/vklochan/python-logstash/blob/2f8b5e7c0befe08d0b39c3929c0a78dbad1bd014/logstash/formatter.py
class StashwardFormatter(logging.Formatter):
    def __init__(self, message_type="django"):
        self.host = socket.gethostname()
        self.message_type = message_type

    def get_extra_fields(self, record):
        """Tack on all the fields from the extra parameter on logging calls"""
        # The list contains all the attributes listed in
        # http://docs.python.org/library/logging.html#logrecord-attributes
        skip_list = set([
            'args', 'asctime', 'created', 'exc_info', 'exc_text', 'filename',
            'funcName', 'id', 'levelname', 'levelno', 'lineno', 'module',
            'msecs', 'msecs', 'message', 'msg', 'name', 'pathname', 'process',
            'processName', 'relativeCreated', 'thread', 'threadName', 'extra', 'stack_info'])

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

