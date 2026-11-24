# Builds static honet binaries for all supported targets into dist/.
$ErrorActionPreference = "Stop"
$version = (git describe --tags --always --dirty 2>$null)
if (-not $version) { $version = "dev" }
$targets = @(
    @{ Name = "armv6"; GOARCH = "arm";   GOARM = "6" },
    @{ Name = "armv7"; GOARCH = "arm";   GOARM = "7" },
    @{ Name = "arm64"; GOARCH = "arm64"; GOARM = "" },
    @{ Name = "amd64"; GOARCH = "amd64"; GOARM = "" }
)
$saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; GOARM = $env:GOARM; CGO_ENABLED = $env:CGO_ENABLED }
New-Item -ItemType Directory -Force dist | Out-Null
try {
    foreach ($t in $targets) {
        $env:GOOS = "linux"; $env:GOARCH = $t.GOARCH; $env:GOARM = $t.GOARM; $env:CGO_ENABLED = "0"
        $out = "dist/honet-linux-$($t.Name)"
        go build -trimpath -ldflags "-s -w -X main.version=$version" -o $out ./cmd/honet
        if ($LASTEXITCODE -ne 0) { throw "build failed for $($t.Name)" }
        "{0,-28} {1,8:N1} MB" -f $out, ((Get-Item $out).Length / 1MB)
    }
} finally {
    foreach ($k in $saved.Keys) { Set-Item "env:$k" $saved[$k] }
}
