package serve

import "strings"

// DocumentFromArgument turns a launcher argument into a document path.
//
// Desktop entries register both file associations and the pignus:// scheme, so
// the same command-line slot receives either a path or a URI. A URI carries a
// document plus parameters, and putting one in a filename field would make the
// window show a URL where it expects a file.
//
// A URI that does not parse yields an empty path: opening empty is honest, while
// opening with a malformed string would look like a working document.
func DocumentFromArgument(argument string) string {
	if !strings.HasPrefix(argument, HandlerScheme+"://") {
		return argument
	}

	_, parameters, err := ParseHandlerURI(argument)
	if err != nil {
		return ""
	}
	return parameters["document"]
}
