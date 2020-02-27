@echo off
SET CGO_ENABLED=1
SET GOOS=windows
go build -ldflags "-s -w" -buildmode=c-shared -o proxyg.dll