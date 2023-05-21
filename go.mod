module kk

go 1.18

require (
	github.com/hashicorp/go-uuid v1.0.3
	github.com/jcmturner/gofork v1.7.6
	github.com/jcmturner/gokrb5/v8 v8.4.6
	github.com/jsipprell/keyctl v1.0.3
	github.com/stretchr/testify v1.8.3
	golang.org/x/crypto v0.9.0
	gopkg.in/jcmturner/aescts.v1 v1.0.1
	gopkg.in/jcmturner/dnsutils.v1 v1.0.1
	gopkg.in/jcmturner/goidentity.v3 v3.0.0
	gopkg.in/jcmturner/gokrb5.v7 v7.5.0
	gopkg.in/jcmturner/rpc.v1 v1.1.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/net v0.10.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// replace github.com/jcmturner/gokrb5/v8 => ./third_party/gokrb5/v8
replace github.com/jcmturner/gokrb5/v8 => github.com/m-vinc/gokrb5/v8 v8.4.5-0.20230521082304-a13fba186c63
