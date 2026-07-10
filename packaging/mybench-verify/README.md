# mybench-verify

Zero-context verifier for a [mybench](https://mybench.is) anchors log:

    uvx mybench-verify https://mybench.is/anchors

Thin wrapper around the `mybench` package's verifier
(`python -m mybench.verify`), published separately so the `uvx` one-liner
resolves. How verification works: https://mybench.is/how-it-works
