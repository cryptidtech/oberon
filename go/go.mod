module github.com/mikelodder7/oberon

go 1.17

replace github.com/kilic/bls12-381 => ./bls12-381

require (
	github.com/kilic/bls12-381 v0.1.0
	github.com/stretchr/testify v1.6.1
	golang.org/x/crypto v0.0.0-20211215153901-e495a2d5b3d3
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
)
