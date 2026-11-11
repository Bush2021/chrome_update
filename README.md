# chrome_update

Go packages for getting Chrome from Google: check for builds (`omaha`), download them (`fetch`), unpack them (`unpack`), rebuild them from Zucchini patches (`zucc`) and read Windows executables (`pefile`).

## How it works

### Checking for builds

`omaha` asks Google's update server over [protocol 4](https://chromium.googlesource.com/chromium/src/+/main/docs/updater/protocol_4.md), the protocol Chrome's own updater speaks. The answer is a list of pipelines, each a chain of steps such as download, xz decode, Zucchini patch and CRX3 unpack, with the size and SHA-256 of every file. The server gives the xz stream and the patches only to requests that name Google's updater, so `omaha` names it. A request says whether it is a foreground or a background check (`X-Goog-Update-Interactivity`), and a server that asks background checks to pause (`X-Retry-After`) is reported, capped at 24 hours. Protocol 3 is still there for links to the full installer.

### Downloading

`fetch` downloads a file whose size and SHA-256 are known in advance:

- It resumes where an earlier attempt stopped, with a `Range` request, and checks that the server's `Content-Range` matches.
- It tries each URL once per round and moves to the next URL before retrying one, as the protocol has a client do. Three rounds, with 1 s and 2 s between them; a round that brought new bytes doesn't count.
- A request that goes 30 seconds without a byte, headers included, is given up. A URL that stalls before its first byte is dropped for the rest of that download.
- A file that fails its SHA-256 starts over from the next URL.
- `File.Follow` reads the file while it downloads, so decoding runs alongside the download instead of after it.

### Unpacking

`unpack` decodes xz streams, reads the installer inside a CRX3 package and extracts `CHROME.7Z` from that installer, streaming throughout instead of loading files into memory. The 7z archives are read by `sevenz`, written for Chrome's installer and Chrome++ releases: Copy, LZMA, LZMA2, BCJ, BCJ2 and ARM64 coders, files read in archive order so that a solid folder is decoded once.

### Differential updates

`zucc` runs a pipeline's `zucc` step: it rebuilds the new package from the previous one and a Zucchini patch, through [go-zucchini](https://github.com/404Setup/go-zucchini), and checks the result's size and SHA-256.

### Reading executables

`pefile` reads a Windows executable's architecture, resources, version and imported DLLs on any OS, from an `io.ReaderAt`.

## License

Licensed under [GPL-3.0-or-later](LICENSE).
