package api

//go:generate go run github.com/juju/juju/provider/vsphere/internal/api/generator
//go:generate go run github.com/juju/juju/vendor/github.com/golang/mock/mockgen -source=generated_api.go -destination mocks/api.go -package mocks
