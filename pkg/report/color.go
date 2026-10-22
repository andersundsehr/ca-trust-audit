package report

import "strings"

// TerminalOptions configures only human output; report data and JSON are unchanged.
type TerminalOptions struct {
	Verbose bool
	Color   bool
}

func statusColor(label string) string {
	switch label {
	case "PASSED":
		return "\x1b[32m"
	case "PROBLEM":
		return "\x1b[31m"
	case "NOT VERIFIED", "REVIEW", "PARTIAL":
		return "\x1b[33m"
	case "UNSUPPORTED", "UNAVAILABLE":
		return "\x1b[90m"
	case "COMPLETE":
		return "\x1b[36m"
	}
	return ""
}
func colorTerminal(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if line == "CA Trust Audit" || line == "SUMMARY" || strings.HasPrefix(line, "HOST ") || strings.HasPrefix(line, "CONTAINER ") {
			lines[i] = "\x1b[1m" + line + "\x1b[0m"
			continue
		}
		if strings.HasPrefix(line, "Warning:") {
			lines[i] = "\x1b[33mWarning:\x1b[0m" + strings.TrimPrefix(line, "Warning:")
			continue
		}
		for _, label := range []string{"NOT VERIFIED", "PASSED", "PROBLEM", "REVIEW", "UNSUPPORTED", "UNAVAILABLE", "PARTIAL", "COMPLETE"} {
			start := -1
			if strings.HasPrefix(line, "  "+label+" ") {
				start = 2
			}
			for _, prefix := range []string{"  CA FILES: ", "  LIVE CLIENTS: ", "  Coverage: "} {
				if strings.HasPrefix(line, prefix+label) {
					start = len(prefix)
				}
			}
			if strings.HasPrefix(line, "  Store ") || strings.HasPrefix(line, "  Client ") {
				if at := strings.LastIndex(line, ": "+label+" ("); at >= 0 {
					start = at + 2
				}
			}
			if start >= 0 {
				lines[i] = line[:start] + statusColor(label) + label + "\x1b[0m" + line[start+len(label):]
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}
