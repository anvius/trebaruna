package domain

import (
	"strconv"
	"strings"
)

// defaultLocalPort is the port of a websocket invocation that names none
// (autoscript 1.7).
const defaultLocalPort = 63117

// LocalChannel is the WebSocket channel a page opens (D.1): the ports to
// try in order, the channel protocol (3, or 4; asynchronous 4.1 when the
// page's script is newer, jvc above 3) and the session id the page's
// messages carry.
type LocalChannel struct {
	Ports        []int
	Version      int
	Asynchronous bool
	SessionID    string
}

// ReadLocalChannel reads afirma://websocket?ports=…&v=…&idsession=….
func ReadLocalChannel(invocation Invocation) (LocalChannel, error) {
	channel := LocalChannel{SessionID: invocation.Param("idsession")}
	switch invocation.Param("v") {
	case "3":
		channel.Version = 3
	case "4":
		channel.Version = 4
	default:
		return LocalChannel{}, Failure{Code: UnsupportedProcedure, Cause: "channel version " + invocation.Param("v")}
	}
	if jvc, err := strconv.Atoi(invocation.Param("jvc")); err == nil && jvc > 3 && channel.Version == 4 {
		channel.Asynchronous = true
	}
	if channel.SessionID != "" {
		if err := validSessionID(channel.SessionID); err != nil {
			return LocalChannel{}, err
		}
	}
	ports := invocation.Param("ports")
	if ports == "" {
		channel.Ports = []int{defaultLocalPort}
		return channel, nil
	}
	for _, text := range strings.Split(ports, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(text))
		if port < 0 {
			port = -port
		}
		if err != nil || port == 0 || port > 65535 {
			return LocalChannel{}, Failure{Code: Params, Cause: "ports"}
		}
		channel.Ports = append(channel.Ports, port)
	}
	return channel, nil
}

// MessageSession is the session id a channel message names: the text after
// its first "idsession=" up to the next "&", or to the end without a
// trailing "@EOF".
func MessageSession(message string) string {
	_, rest, found := strings.Cut(message, "idsession=")
	if !found {
		return ""
	}
	if value, _, found := strings.Cut(rest, "&"); found {
		return value
	}
	return strings.TrimSuffix(rest, "@EOF")
}

// BySocket is an operation as a page sends it over the local channel: the
// answer goes back on the socket, so the intermediate server's parameters
// (and its cipher) do not apply; over protocol 4 the channel's version is
// the operation's.
func BySocket(invocation Invocation, channel LocalChannel) Invocation {
	invocation = invocation.Without("stservlet", "rtservlet", "fileid", "id", "key", "cipher", "aw")
	if channel.Version == 4 {
		invocation = invocation.With("ver", "4")
	}
	return invocation
}
