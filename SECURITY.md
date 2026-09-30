# Security

Security is the whole point of the Plug, so reports are very welcome.

## Reporting a hole
**Please don't open a public issue for a security problem.** Use GitHub's private
**"Report a vulnerability"** button (Security tab of this repository). That way it can be fixed
before anyone can abuse it. Please include:
- what you did (the smallest example that shows it),
- what happened, and what you expected,
- which part: packer, verifier, socket, gateway, helper, dashboard.

## What counts
Anything that performs a risky action (key, signing, going online, scans, device switches, turning
strict mode off) without a person pressing and holding, or in strict mode without "yes" in the terminal.
Anything that lets a plug do something it didn't declare, run after being changed, reach your
own computer or network, read the page around it, fake a prompt, or get past the watchdog.
Also anything that lets another website talk to the local helper.

## Known limits
These are known and don't need reporting, but ideas for closing them are welcome.
- **Navigating away:** a browser can't stop a sandboxed frame loading a new address. The watchdog
  sees it and pulls the plug, but that one request may already have left. At most one leak, then it's dead.
- **WebRTC:** browser security rules don't cover it yet. It is removed before the plug's code runs;
  this is a patch, not a wall.
- **DNS tricks:** the gateway checks names, not the address a name points to.
- **CPU:** a plug can still keep its own frame busy.
