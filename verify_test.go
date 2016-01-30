package verify

import "testing"

var secret = `ruiyh684i7ug87\4ruiyh684i7ug87\4`

func TestCreateAndParse(t *testing.T) {
	var startStr = "2317083"
	var sourceHash = CreateHash()
	str := Create(startStr, sourceHash, secret)

	dest, hash, _ := Parse(str, secret)
	if dest != startStr {
		t.Error("Invalid create or parse")
	}
	if !CheckHash(hash, sourceHash, secret) {
		t.Error("Invalid source hash")
	}
}
func TestParseShortCode(t *testing.T) {
	var code = "sdfsd"
	var _, _, err = Parse(code, secret)
	if err == nil {
		t.Error("Need error")
	}
}
func TestParse(t *testing.T) {
	var code = "PGtXfb4H5CMJAmXNLBROFx3A5HxvTuarg6BybPUnpDs=.546d92bb2c600359dd9c04e48ad873fdfcadb8c3"
	var str, keyHash, err = Parse(code, secret)

	if str != "0000000002317083" {
		t.Log(str, keyHash, err)
		t.Error("Invalid str")
	}
	if keyHash != sha1get("f39675ac2cbc33c4fedc838343b2cb75abdb6d2c"+secret) {
		t.Error("Invalid key hash")
	}

	code = "jZdK4dH41x2Z1t40XkNO2ML0CilZRkrG87locq8zBNY=.0f080043fa62997e42abf16208235b686b014715"
	str, keyHash, err = Parse(code, secret)
	if str != "0000000002317083" {
		t.Log(str, keyHash, err)
		t.Error("Invalid str")
	}
	if keyHash != sha1get("4ee5de9c0b36427a07376d8b85e9f48874fb642c"+secret) {
		t.Error("Invalid key hash")
	}
	if err != nil {
		t.Error(err)
	}
}
