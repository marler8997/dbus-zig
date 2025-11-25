# dbus-zig

A dbus library for Zig.

See [example.zig](example.zig)


# Notes on DBUS

DBUS is a single process that accepts unix socket connections and ferries data between them. Each client/process has at least 1 globally unique name (i.e. `org.freedesktop.NetworkManager`). Each client can expose many objects, each with their own "path" (i.e. `/org/freedesktop/UPower`). Each object can also expose multiple "interfaces" (i.e. `org.freedesktop.DBUS.Properties`). Clients on the bus can send method calls to other clients (or the DBUS itself) by specifying the destination name, object path, interface and "member" (method name). These messages should receive a "method return" message once handled.

> It's valid for a method call to omit the interface so long as the method name is unique amongst all interfaces that a particular object exposes, but this is brittle and not recommended.

Clients can also send "signals" which are messages that don't expect a response.  These can be sent to all objects by omitting the "destination" in the message. Method calls can also omit the destination so it broadcasts to every object but this is more common for signals. 

The name of the DBUS itself is always `org.freedesktop.DBus`.  To list all the connected clients you can call `org.freedesktop.DBUS.ListNames` on the `/org/freedesktop/DBus` object, i.e.

```
busctl call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ListNames ""
```

You can view the entire client/object tree with:
```
busctl tree [--system | --user]
```

Given a client/object, you can list its interfaces and the methods on them with:
```
busctl introspect [--system | --user] <DESTINATION> <PATH>
```
i.e.
```
busctl introspect --user org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop
```
