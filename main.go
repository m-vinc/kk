package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"os/user"
	"regexp"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jsipprell/keyctl"
)

const (
	persistentKrbKey    = "_krb"
	krbPrimaryKey       = "krb_ccache:primary"
	krbDefaultPrincipal = "__krb5_princ__"
)

var (
	krbCacheKeyReg = regexp.MustCompile("^")
)

func getPersistent() (keyctl.Keyring, error) {
	cu, err := user.Current()
	if err != nil {
		return nil, err
	}

	k, err := keyctl.UserSessionKeyring()
	if err != nil {
		return nil, err
	}
	persistentName := fmt.Sprintf("_persistent.%s", cu.Uid)
	pk, err := keyctl.OpenKeyring(k, persistentName)
	if err != nil {
		return nil, err
	}

	krbk, err := keyctl.OpenKeyring(pk, persistentKrbKey)
	if err != nil {
		return nil, err
	}

	return krbk, nil
}

func printKeys(k keyctl.Keyring) error {
	ks, err := keyctl.ListKeyring(k)
	if err != nil {
		return err
	}

	for _, kk := range ks {
		log.Println(kk.Info())
	}
	return nil
}

func getValidCredentials(k keyctl.Keyring) ([]byte, []byte, error) {
	p, err := k.Search(krbPrimaryKey)
	if err != nil {
		return nil, nil, err
	}

	primaryCacheKey, err := p.Get()
	if err != nil {
		return nil, nil, err
	}

	if len(primaryCacheKey) < 8 {
		return nil, nil, fmt.Errorf("cannot parse primary cache name")
	}

	//version := binary.BigEndian.Uint32(primaryCacheKey[:4])
	length := binary.BigEndian.Uint32(primaryCacheKey[4:8])
	primaryCacheName := string(primaryCacheKey[8:])

	if length > uint32(len(primaryCacheKey)-8) {
		return nil, nil, fmt.Errorf("bad data ?")
	}

	pk, err := keyctl.OpenKeyring(k, string(primaryCacheName))
	if err != nil {
		log.Println("error while opening", k, string(primaryCacheName))
		return nil, nil, err
	}

	kdpk, err := pk.Search(krbDefaultPrincipal)
	if err != nil {
		return nil, nil, err
	}

	defaultPrincipal, err := kdpk.Get()
	if err != nil {
		return nil, nil, err
	}

	princ, _, err := UnmarshalPrincipal(defaultPrincipal)
	if err != nil {
		return nil, nil, err
	}

	if len(princ.Items) < 1 {
		return nil, nil, fmt.Errorf("the username must be contains within ccache principal")
	}

	ticketKey := fmt.Sprintf("krbtgt/%[1]s@%[1]s", princ.Realm)

	log.Println("search key with name", ticketKey)

	credKey, err := pk.Search(ticketKey)
	if err != nil {
		return nil, nil, err
	}

	creds, err := credKey.Get()
	if err != nil {
		return nil, nil, err
	}

	return creds, defaultPrincipal, nil

	// waste of what I've done to understand the keyring ccache format
	//	pos := 0
	//
	//	log.Println("remaining data", ccache[pos:], len(ccache[pos:]))
	//
	//	client, readed, err := UnmarshalPrincipal(ccache)
	//	if err != nil {
	//		return err
	//	}
	//	pos += readed
	//	log.Println("client", client, pos, err)
	//
	//	server, readed, err := UnmarshalPrincipal(ccache[pos:])
	//	if err != nil {
	//		return err
	//	}
	//	log.Println("server", server, string(server.Items[0]), string(server.Items[1]), pos, err)
	//
	//	pos += readed
	//
	//	log.Println("remaining data", ccache[pos:], len(ccache[pos:]))
	//
	//	enctype := binary.BigEndian.Uint16(ccache[pos : pos+2])
	//	pos += 2
	//
	//	//enctype := binary.BigEndian.Uint16(ccache[pos : pos+2])
	//	//pos += 2
	//
	//	log.Println(enctype)
	//
	//	keyLength := binary.BigEndian.Uint32(ccache[pos : pos+4])
	//	pos += 4
	//	key := binary.BigEndian.Uint32(ccache[pos : pos+int(keyLength)])
	//
	//	pos += int(keyLength)
	//	log.Println(keyLength, key)
	//
	//	log.Println("remaining data", ccache[pos:], len(ccache[pos:]))
	//
	//	authTime := binary.BigEndian.Uint32(ccache[pos : pos+4])
	//	pos += 4
	//
	//	startTime := binary.BigEndian.Uint32(ccache[pos : pos+4])
	//	pos += 4
	//
	//	endTime := binary.BigEndian.Uint32(ccache[pos : pos+4])
	//	pos += 4
	//
	//	renewTill := binary.BigEndian.Uint32(ccache[pos : pos+4])
	//	pos += 4
	//
	//	isSKey := ccache[pos : pos+1]
	//	pos += 1
	//
	//	ticketFlag := binary.BigEndian.Uint32(ccache[pos : pos+4])
	//	pos += 4
	//
	//	addressCount := binary.BigEndian.Uint32(ccache[pos : pos+4])
	//	pos += 4
	//
	//	log.Printf("found %d addresses", addressCount)
	//	addresses := [][]byte{}
	//
	//	for i := 0; i < int(addressCount); i++ {
	//		apos := pos
	//		// addrType := ccache[apos : apos+2]
	//		apos += 2
	//
	//		addrLength := binary.BigEndian.Uint32(ccache[apos : apos+4])
	//		apos += 4
	//
	//		//addr := binary.BigEndian.Uint32(ccache[pos:pos+addrLength])
	//		apos += int(addrLength)
	//
	//		addresses = append(addresses, ccache[pos:apos])
	//		pos += 8 + int(addrLength)
	//	}
	//
	//	authDataCount := binary.BigEndian.Uint32(ccache[pos : pos+4])
	//	pos += 4
	//
	//	log.Printf("found %d auth data", authDataCount)
	//	authData := [][]byte{}
	//
	//	for i := 0; i < int(authDataCount); i++ {
	//		apos := pos
	//		// addrType := ccache[apos : apos+2]
	//		apos += 2
	//
	//		authLength := binary.BigEndian.Uint32(ccache[apos : apos+4])
	//		apos += 4
	//
	//		//addr := binary.BigEndian.Uint32(ccache[pos:pos+addrLength])
	//		apos += int(authLength)
	//
	//		authData = append(authData, ccache[pos:apos])
	//		pos += 8 + int(authLength)
	//	}
	//
	//	ticketLength := binary.BigEndian.Uint32(ccache[pos : pos+4])
	//	pos += 4
	//
	//	ticket := ccache[pos : pos+int(ticketLength)]
	//	pos += int(ticketLength)
	//
	//	log.Println(authTime, startTime, endTime, renewTill, isSKey, ticketFlag, addresses, authData, ticket, len(ticket))
	//	log.Println("remaining data", ccache[pos:], len(ccache[pos:]))
	//
	//	log.Println(base64.StdEncoding.EncodeToString(ticket))
	//
	//	// Ignore second ticket for now
	//	//pos =
	//
	//	//	log.Println(ccache)
	//
	//	//k5_input_init(&in, data, len);
	//	//creds->client = unmarshal_princ(&in, version);
	//	//creds->server = unmarshal_princ(&in, version);
	//	//unmarshal_keyblock(&in, version, &creds->keyblock);
	//	//creds->times.authtime = get32(&in, version);
	//	//creds->times.starttime = get32(&in, version);
	//	//creds->times.endtime = get32(&in, version);
	//	//creds->times.renew_till = get32(&in, version);
	//	//creds->is_skey = k5_input_get_byte(&in);
	//	//creds->ticket_flags = get32(&in, version);
	//	//creds->addresses = unmarshal_addrs(&in, version);
	//	//creds->authdata = unmarshal_authdata(&in, version);
	//	//get_data(&in, version, &creds->ticket);
	//	//get_data(&in, version, &creds->second_ticket);
}

func main() {
	k, err := getPersistent()
	if err != nil {
		log.Fatal(err)
	}

	kcred, defprinc, err := getValidCredentials(k)
	if err != nil {
		log.Fatal(err)
	}

	ccache, err := credentials.LoadKeyringCCache(kcred, defprinc)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(ccache)

	cfg, err := config.Load("/etc/krb5.conf")
	if err != nil {
		log.Fatal(err)
	}

	cl, err := client.NewFromCCache(ccache, cfg)
	if err != nil {
		log.Fatal(err)
	}

	log.Println(cl)

	r, _ := http.NewRequest("GET", "http://a-spnego-protected-service:1337", nil)
	spnegoCl := spnego.NewClient(cl, nil, "")
	resp, err := spnegoCl.Do(r)
	log.Println(resp, err)
}
