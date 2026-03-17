# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

A static file server written in Go using only the standard library. Serves a directory over HTTP and optionally HTTPS with configurable ports. Single-file architecture in `main.go`.

## Build & Run

```sh
go build -o webserver .        # compile binary
go run main.go -dir ./public   # run without compiling a binary
```

## Code Conventions

- The project owner is new to Go — include comments that explain Go-specific idioms and patterns (goroutines, channels, interfaces, error handling, pointers) when introducing them.
- Uses standard library only — no external dependencies. Prefer `net/http`, `crypto/tls`, etc. over third-party packages.
- Middleware follows the `func(http.Handler) http.Handler` wrapping pattern.
- The compiled binary (`webserver`) should not be committed.
