package lastpass_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/veloceapps/lastpass-go"
)

var _ = Describe("Errors", func() {
	Describe("AccountNotFoundError", func() {
		var acctID = "123"
		var err error = &AccountNotFoundError{acctID}

		Describe("Error()", func() {
			It("provides error message including account ID", func() {
				Expect(err).To(MatchError("could not find LastPass account with ID=" + acctID))
			})
		})
	})
})
