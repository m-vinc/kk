# Retrieve kerberos credentials from the linux kernel keyring

I'm currently using the [gokrb5](https://github.com/jcmturner/gokrb5) library to communicate with "spnego protected" services and need to find a way to load and use credential stored in the linux kernel keyring used when kerberos use the `default_ccache_name = KEYRING:persistent:%{uid}` option instead of a traditional file like `/tmp/krb5cc_%{uid}`.

After searching for someone who already did it (didn't find it honestly) I started working on a poc to know if this is possible or if I need to switch my kerberos config to use file, I'm totally new on all this kerberos file or ccache format and my knowledge of these things is mostly from reading the code from [krb5 ccache source directory](https://github.com/krb5/krb5/blob/master/src/lib/krb5/ccache) so I don't know if what I expose here is totally obvious or not recommended or anything like that. Don't hesitate to tell me if I'm wrong !

## Retrive credentials from the keyring

At the very begining I'm just seeking of how the klist command retrieve these credentials with `strace` and other thing like that and notice some `keyctl(KEYCTL_READ` and `keyctl(KEYCTL_SEARCH` syscalls which lead me to read more about linux keyring and how to set and retrieve key from a user persistent keyring used by kerberos.

Note that all of the data retrived from these keys need to be unmarshal using the format describe [here](https://github.com/krb5/krb5/blob/master/src/lib/krb5/ccache/ccmarshal.c)

```
# retrive the user's persistent keyring id
$ export KEYRING=$(keyctl get_persistent @u)
882811894
# list all the keys and child keyring
$ keyctl show $k
Keyring
 882811894 ---lswrv  1000 65534  keyring: _persistent.1000
 645549956 --alswrv  1000 1000   \_ keyring: _krb
 167745626 --alswrv  1000 1000       \_ user: krb_ccache:primary
 291162908 --alswrv  1000 1000       \_ keyring: krb_ccache_7wzjShP
 951443387 --alswrv  1000 1000           \_ user: __krb5_princ__
 743267377 --alswrv  1000 1000           \_ user: krbtgt/TOTO.FR@TOTO.FR
```

We can get the cache entry to use by reading the value of the `krb_ccache:primary` key :

```
$ keyctl pipe 167745626 | hexdump -C
00000000  00 00 00 01 00 00 00 12  6b 72 62 5f 63 63 61 63  |........krb_ccac|
00000010  68 65 5f 37 77 7a 6a 53  68 50                    |he_7wzjShP|
0000001a
```

Also we can get the principal of the cache entry by reading the `__krb5_princ__` key :

```
$ keyctl pipe 951443387 | hexdump -C
00000000  00 00 00 01 00 00 00 01  00 00 00 07 54 4f 54 4f  |............TOTO|
00000010  2e 46 52 00 00 00 06 6d  2d 76 69 6e 63 0a        |.FR....m-vinc.|
0000001e
```

And finally we can retrive the credential part by reading the final key `krbtgt/TOTO.FR@TOTO.FR` :

```
$ keyctl pipe 743267377 | hexdump -C
[REDACTED]
```

Sure we can use the `exec` go package to search and read for these key but someone already create a package to do the job and better than calling the binary, by calling the syscalls : https://github.com/jsipprell/keyctl


In the `main.go` file the is the example of a simple read of these key to determine which key to read use.

Now let's talk about the part I'm the most lost : using existing structure `CCache` in gokrb5 to initialize a `client` and use it to perform spnego http request like that for example :

```go
    // these variable is what we retrieve from keyring
    // kcred is the content of the krbtgt/TOTO.FR@TOTO.FR keyring key
    // defprinc is the Default principal we got from reading the __krb5_princ__ key
	kcred, defprinc, err := getValidCredentials(k)
	if err != nil {
		log.Fatal(err)
	}

    // We'll talk about that function later, for the moment just notice the usage of the two variables above
	ccache, err := credentials.LoadKeyringCCache(kcred, defprinc)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(ccache)

	cfg, err := config.Load("/etc/krb5.conf")
	if err != nil {
		log.Fatal(err)
	}

    // Initialize the kerberos client with the result of the LoadKeyringCCache function
	cl, err := client.NewFromCCache(ccache, cfg)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(cl)

	r, _ := http.NewRequest("GET", "http://a-spnego-protected-service:1337", nil)
	spnegoCl := spnego.NewClient(cl, nil, "")
	resp, err := spnegoCl.Do(r)

    // The spnego work as expected like when reading a krb5cc_{uid} cache
	log.Println(resp, err)
```

Here is the `LoadKeyringCCache` function in the `gokrb5/v8/credentials/ccache.go` file :

```go
// Umarshal the credential from what we retrieve from the KEYRING: ccache type on linux
// In the file format ccache we got the default principal
// Some version check is not performed since I understand only version 4 is used in KEYRING ccache type
// This function doesn't take care of retrieving the data from the keyring, you can achieve it with the "github.com/jsipprell/keyctl" or just calling the keyctl binary
// https://github.com/krb5/krb5/blob/e991aecd44d9d953e7ceb928f994fd07a0105433/src/lib/krb5/ccache/ccmarshal.c#L35
func LoadKeyringCCache(credential []byte, defaultPrincipal []byte) (*CCache, error) {
	c := new(CCache)
	c.Version = 4
	pd := 0
	p := 0

	// We assume the version of the ccache is 4 since we read data from keyring
	var endian binary.ByteOrder
	endian = binary.BigEndian

	// There is no header in what we retrive from keyring, found no documentation about that header so I assume this is a file format specific thing ?
	//err := parseHeader(credential, &p, c, &endian)
	//if err != nil {
	//	return nil, err
	//}

	cred, err := parseCredential(credential, &p, c, &endian)
	if err != nil {
		return nil, err
	}

	// In the keyring the defaultPrincipal is not included in the same data as the credential, so we pass it through an other agument and parse in with his own index `pd` and pass the same ccache struct since the data share the same endian property as the credential data
	c.DefaultPrincipal = parsePrincipal(defaultPrincipal, &pd, c, &endian)
	c.Credentials = []*Credential{cred}

	return c, nil
}
```

Baiscally I initialize a `CCache` struct and define two index variable called `p` and `pd` for `position` and `position defaultPrincipal` since the default principal is not included in credential data we need to maintain two index instead of just one.

I include comments on the parseHeader part because I don't found any references of that header, I'm maybe wrong.

With this method I successfully use the spnego http client without any problem, I'll do more test with my usage of course.
