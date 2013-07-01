package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/gokyle/sshkey"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func ReadPrompt(prompt string) (in string, err error) {
	fmt.Printf("%s", prompt)
	rd := bufio.NewReader(os.Stdin)
	line, err := rd.ReadString('\n')
	if err != nil {
		return
	}
	in = strings.TrimSpace(line)
	return
}

func checkKeyType(keytype string) {
	switch keytype {
	case "rsa":
		return
	case "ecdsa":
		return
	default:
		fmt.Println("bad key type")
		os.Exit(1)
	}
}

func checkErr(err error) {
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func main() {
	flComment := flag.String("c", "", "key comment")
	flFile := flag.String("f", "", "input keyfile")
	flFpr := flag.Bool("l", false, "show fingerprint of keyfile")
	flType := flag.String("t", "ecdsa", "type of key to create")
	flSize := flag.Int("b", 256, "bitsize of key to create")
	flag.Parse()

	checkKeyType(*flType)
	if *flComment == "" {
		*flComment = getDefaultComment()
	}

	if *flType == "rsa" && *flSize == 256 {
		*flSize = 2048
	}

	if *flFpr {
		fingerprint(*flFile, *flType)
	} else {
		keygen(*flFile, *flType, *flComment, *flSize)
	}
}

func defaultKey(keytype string) string {
	home := os.Getenv("HOME")
	defkey := filepath.Join(home, ".ssh", "id_"+keytype)
	return defkey
}

func fingerprint(keyfile string, keytype string) {
	var err error

	if keyfile == "" {
		defkey := defaultKey(keytype)
		defkey += ".pub"
		prompt := fmt.Sprintf("Enter file in which the key is (%s): ", defkey)
		keyfile, err = ReadPrompt(prompt)
		checkErr(err)
		if keyfile == "" {
			keyfile = defkey
		}
	}
	pub, err := sshkey.LoadPublicKeyFile(keyfile, true)
	checkErr(err)

	fpr, err := sshkey.FingerprintPretty(pub, 0)
	checkErr(err)

	comment := pub.Comment
	if comment == "" {
		comment = keyfile
	}

	fmt.Printf("%d %s %s (%s)\n", pub.Size(), fpr, comment, strings.ToUpper(keytype))
	os.Exit(0)
}

func keygen(keyfile, keytype, comment string, size int) {
	var (
		err error
		key interface{}
	)

	switch keytype {
	case "rsa":
		fmt.Println("Generating public/private rsa key pair.")
		key, err = sshkey.GenerateSSHKey(sshkey.KEY_RSA, size)
		checkErr(err)
	case "ecdsa":
		fmt.Println("Generating public/private ecdsa key pair.")
		key, err = sshkey.GenerateSSHKey(sshkey.KEY_ECDSA, size)
		checkErr(err)
	}

	if keyfile == "" {
		defkey := defaultKey(keytype)
		prompt := fmt.Sprintf("Enter file in which to save the ke (%s): ", defkey)
		keyfile, err = ReadPrompt(prompt)
		checkErr(err)
		if keyfile == "" {
			keyfile = defkey
		}
	}

	var password string
	for {
		password, err = sshkey.PasswordPrompt("Enter password (empty for no passphrase): ")
		checkErr(err)
		if password != "" {
			var password2 string
			password2, err = sshkey.PasswordPrompt("Enter password again: ")
			checkErr(err)
			if password != password2 {
				fmt.Println("Passphrases do not match. Try again.")
				continue
			}
			break
		} else {
			break
		}
	}

	privout, err := sshkey.MarshalPrivate(key, password)
	checkErr(err)

	pub := sshkey.NewPublic(key, comment)
	if key == nil {
		fmt.Println("Failed to create a public key.")
		os.Exit(1)
	}

	pubout := sshkey.MarshalPublic(pub)
	if pubout == nil {
		fmt.Println("Failed to create a public key.")
		os.Exit(1)
	}

	err = ioutil.WriteFile(keyfile, privout, 0600)
	checkErr(err)
	err = ioutil.WriteFile(keyfile+".pub", pubout, 0644)
	checkErr(err)
}

func getDefaultComment() string {
	cmd := exec.Command("whoami")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	whoami := strings.TrimSpace(string(out))

	cmd = exec.Command("hostname")
	out, err = cmd.Output()
	if err != nil {
		return ""
	}
	hostname := strings.TrimSpace(string(out))

	return fmt.Sprintf("%s@%s", whoami, hostname)
}
