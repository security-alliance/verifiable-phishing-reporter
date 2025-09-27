# Verifiable Phishing Reporter

This is a tool meant for advanced users and security researchers ONLY. Do not run this tool if you do not know what you are doing.

## Usage

To run this tool, simply do the following:

```
npx @security-alliance/verifiable-phishing-reporter
```

This will generate a self-signed root CA (which you will need to install) and run a HTTP proxy on port 8443. If you can't figure out how to install the root CA, you probably shouldn't be using this tool.

Next, you need to configure whatever application you're using to use the HTTP proxy. On Chromium browsers, we recommend the FoxyProxy extension.

Finally, visit the page that you believe is malicious. The reporter will automatically submit attestations as they become available.

## Configuration
If you want to exclude specific connections from being submitted, create a file called `excluded.txt` in `$HOME/.config/verifiable-phishing-reporter`. Each line should contain a single hostname, case sensitive.

If you need to change the port that the HTTP proxy is listening on, use the `PORT` environment variable:
```
PORT=8080 npx @security-alliance/verifiable-phishing-reporter
```

If you need to set a SOCKS proxy (for example, to use a residential proxy), use the `PROXY` environment variable:
```
PROXY=socks5://1.2.3.4:4321 npx @security-alliance/verifiable-phishing-reporter
```

If we ever turn on authentication, or if you would like to be credited for your submissions, use the `SEAL_API_KEY` environment variable:
```
SEAL_API_KEY=sk_placeholder npx @security-alliance/verifiable-phishing-reporter
```

If you want to turn on verbose logging, use the `DEBUG` environment variable:
```
DEBUG=true npx @security-alliance/verifiable-phishing-reporter
```

## Troubleshooting

### The connection is opened but no attestation is generated
There may be a keepalive which is preventing the TLS connection from terminating. Close the tab.

### I'm sure that the page is malicious, but the reporter is not blocking it
The page may be loading a static asset which has been cached. Becaues it was cached, the browser will not load it again, which means no attestation can be generated for the request/response. Clear your browser's cache and try again.

### I cleared my cache and it's still not being blocked
Send us the attestations that you believe indicate malicious activity, as well as any additional information you may hvave. You can reach us through the [SEAL Tips Bot](https://t.me/seal_tips_bot).
