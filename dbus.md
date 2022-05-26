https://dbus.freedesktop.org/doc/dbus-specification.html

# Message Format

Each message has a header and body.  Header must be 0-padded to 8-bytes but not the body.
Maximum message length is `2^27` (128 MiB).

Header signature is `yyyyuua(yv)`, here is a table of the fields:

|len| name             | description and/or values                                         |
|---|------------------|-------------------------------------------------------------------|
| 1 | endian           | 'l' for little-endian and 'B' for big-endian                      |
| 1 | message_type     | 1=method_call, 2=method_return, 3=error_reply, 4=signal           |
| 1 | flags            | 1=no_reply_expected, 2=no_auto_start, 4=allow_interactive_auth    |
| 1 | proto_version    | should be 1                                                       |
| 4 | body_length      | length of message body in bytes                                   |
| 4 | serial           | used as a cookie to identify a reply with a corresponding request |
| N | fields           | array of 0 or more fields which are a 1-byte-code/value pairs     |

The following are the header field codes:
 code
  |
| V | name        | type        | Required In        |
|---|-------------|-------------|--------------------|
| 1 | path        | object_path | method_call/signal |
| 2 | interface   | string      | signal |
| 3 | member      | string      | signal |
| 4 | error_name  | string      | error |
| 5 | reply_serial| u32         | error,method_return |
| 6 | destination | string      | optional |
| 7 | sender      | string      | optional |
| 8 | signature   | signature   | optional |
| 9 | unix_fds    | u32         | optional |

# Names

* maximum name length is 255 (applies to bus names, interfaces and members)

### Interface Names

Required:

* 2 or more elements separated `.`
* elements consist of `[A-Za-z0-9_]` and must not begin with a digit

Recommended:

* should start with a reversed DNS name of the author in lower case (like interface names in Java)
* the rest of the interface name should be CamelCase
* it's a good idea to include the major version of the interface in the name
* since interface names can't have `-`, replace them with `_` when necessary
* elements that start with a digit should use an `_` prefix

### Bus Names

> TODO: fill in this section

### Member Names

> TODO: fill in this section

### Error Names

* same restrictions as interface names
* usually consists of <interface-name>.Error.<error-name>
