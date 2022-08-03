package enclave

import (
	"flag"
	"os"
	"testing"

	"github.com/findy-network/findy-agent-auth/user"
	"github.com/lainio/err2/try"
	"github.com/stretchr/testify/assert"
)

const dbFilename = "fido-enclave.bolt"

const emailAddress = "test@email.com"
const emailNotCreated = "not@exists.email"

func TestMain(m *testing.M) {
	try.To(flag.Set("logtostderr", "true"))
	try.To(flag.Set("v", "3"))

	setUp()
	code := m.Run()
	tearDown()
	os.Exit(code)
}

func setUp() {
	_ = os.RemoveAll(dbFilename)
	_ = InitSealedBox(dbFilename, "", "")
}

func tearDown() {
	WipeSealedBox()
}

func TestNewUser(t *testing.T) {
	u := user.NewUser(emailAddress, emailAddress, "")
	err := PutUser(u)
	assert.NoError(t, err)

	err = PutUser(u)
	assert.NoError(t, err)
}

func TestGetUser(t *testing.T) {
	u, found, err := GetUser(emailAddress)
	assert.NoError(t, err)
	assert.True(t, found)
	assert.NotNil(t, u)

	_, found, err = GetUser(emailNotCreated)
	assert.NoError(t, err)
	assert.False(t, found)
}

func TestGetExistingUser(t *testing.T) {
	u, err := GetExistingUser(emailAddress)
	assert.NoError(t, err)
	assert.NotNil(t, u)

	_, err = GetExistingUser(emailNotCreated)
	assert.Error(t, err)
}
