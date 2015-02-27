# Stashward

[![Build Status](https://travis-ci.org/PSU-OIT-ARC/stashward.svg?branch=master)](https://travis-ci.org/PSU-OIT-ARC/stashward)

Stashward is a log formatter and handler for Python that implements the (poorly specified)
logstash-forwarder protocol.

The protocol is described in what *appears* to be good enough detail here:
https://github.com/elasticsearch/logstash-forwarder/blob/master/PROTOCOL.md

But if you implement the protocol as described, you will crash logstash every time
you send a data packet to it.

The trick is that there are three **required** key/value pairs: host, line and
offset. Those must be sent with every packet. And you also **cannot** send an
`@timestamp` field. I do not know if that is a logstash-forwarder issue, or a
logstash issue.

# Security

Following logstash-forwarder's lead, a server SSL certificate is required, and
it must be signed by a CA. The common name on the certificate must match the
host you are connecting to.

# Usage

```python
import logging
from stashward import StashwardHandler

root = logging.getLogger('')
root.setLevel(logging.INFO)

# give it a host, and port where logstash forwarder is listening, and the path
# to a CA file
handler = StashwardHandler("example.com", 5043, ca_certs="/etc/pki/tls/certs/ALL_CAs.crt")
root.addHandler(handler)

# log something
logging.info("Foo")

# log something with an exception
try:
    raise ValueError("foo")
except ValueError:
    logging.exception("Foobar!")
```

# Example Logstash Config

```
input {
    lumberjack {
        port => 5043
        type => "lumberjack"
        ssl_key => "/etc/logstash/private.key"
        ssl_certificate => "/etc/logstash/a_CA_signed_certificate_file.crt"
    }
}

output {
    elasticsearch {
        host => localhost
        protocol => http
    }
}
```

# Testing

The unit tests can be run in Python2 and Python3 by running:

    make test
