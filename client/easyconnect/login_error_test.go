package easyconnect

import (
	"strings"
	"testing"
)

func TestParseLoginErrorAccountDisabled(t *testing.T) {
	body := `<?xml version="1.0" encoding="utf-8"?>
<Auth>
	<Note><![CDATA[User account is disabled!]]></Note>
	<ErrorCode>20007</ErrorCode>
	<Result>0</Result>
	<Message><![CDATA[not allow to login now]]></Message>
</Auth>`
	err := parseLoginError(body)
	if err == nil {
		t.Fatal("parseLoginError returned nil")
	}
	if err.ErrorCode != "20007" || !strings.Contains(err.Error(), "User account is disabled") {
		t.Fatalf("unexpected login error: %+v / %v", err, err)
	}
}

func TestParseLoginErrorUnknownBody(t *testing.T) {
	if err := parseLoginError("not xml"); err != nil {
		t.Fatalf("unexpected parse result: %v", err)
	}
}
