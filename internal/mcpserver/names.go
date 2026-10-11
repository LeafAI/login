package mcpserver

// The tools, named for what they act on. A session is what a person's one-time login produces; a site is something
// securl can reach; the vault holds every secret; archery_* are the SQL tools for one product.
//
// Every name that appears in a result's next_tool, in a hint or in the instructions comes from here, so a rename is a
// change to this block and nothing can be left pointing at a tool that no longer exists.
const (
	toolSessionOpen  = "session_open"  // get a session for a site: asks a person to type the credential once
	toolSessionWait  = "session_wait"  // keep waiting for a session that was asked for
	toolSessionList  = "session_list"  // which sites have a session (never the credentials)
	toolSessionClose = "session_close" // forget a session
	toolRequest      = "request"       // send an HTTP request to a site with the session's credentials; they never reach the agent
	toolSiteList     = "site_list"     // which sites securl can reach
	toolVaultStatus  = "vault_status"
	toolVaultUnlock  = "vault_unlock"

	nextSessionWait = toolSessionWait
	nextArcheryWait = "archery_wait"
	nextVaultUnlock = toolVaultUnlock
)

// The resources an MCP client can read.
const (
	uriSites    = "securl://sites"
	uriSessions = "securl://sessions"
	uriPolicy   = "securl://policy"
)

// Hints are the text of ToolError.Hint that tells an agent which tool to call next.
const (
	archerySessionHint = "Call " + toolSessionOpen + " with force_refresh=true, then retry."
	unlockHintLocked   = "Call " + toolVaultUnlock + ": the user gets a DingTalk link and types the vault passphrase on that page. The agent never sees it."
	unlockHintNone     = "Ask the user to run `securl vault init` once and choose a passphrase of at least 16 characters."
)

// Hints for the request tool.
const (
	noSessionHint      = "There is no session for this site yet. Call " + toolSessionOpen + ": a person types the credential once, then " + toolRequest + " uses it."
	requestExpiredHint = "The site no longer accepts the session. Call " + toolSessionOpen + " with force_refresh=true, then repeat the request."
)
