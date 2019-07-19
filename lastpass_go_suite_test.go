package lastpass_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestLastpassGo(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "LastpassGo Suite")
}
