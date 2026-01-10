#!/usr/bin/env bash

buf generate
find ./api/ -name *.pb.go \
    | xargs -I{} bash -c 'goimports {} >> {}.tmp && mv {}.tmp {}'
