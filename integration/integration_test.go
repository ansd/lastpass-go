package integration_test

import (
	"context"

	. "github.com/ansd/lastpass-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Integration", func() {
	Context("when account exists", func() {
		var newAcct *Account

		BeforeEach(func() {
			newAcct = &Account{
				ID:       "",
				Name:     "test site",
				Username: "test user",
				Password: "test pwd",
				URL:      "https://testURL",
				Group:    "test group",
				Notes:    "test notes",
			}
			Expect(client.Add(context.Background(), newAcct)).To(Succeed())
		})

		AfterEach(func() {
			Expect(client.Delete(context.Background(), newAcct.ID)).To(Succeed())
		})

		Describe("Add()", func() {
			It("adds the account", func() {
				acct, err := accountForID(client, newAcct.ID)
				Expect(err).NotTo(HaveOccurred())
				Expect(acct).To(Equal(newAcct))
			})
		})

		Describe("Accounts()", func() {
			It("lists accounts", func() {
				accts, err := client.Accounts(context.Background())
				Expect(err).NotTo(HaveOccurred())
				Expect(accts).To(ContainElement(newAcct))
			})
		})

		Describe("Update()", func() {
			It("updates the account", func() {
				newAcct.Username = "updated user"
				newAcct.Password = "updated pwd"
				Expect(client.Update(context.Background(), newAcct)).To(Succeed())

				acct, err := accountForID(client, newAcct.ID)
				Expect(err).NotTo(HaveOccurred())
				Expect(acct).To(Equal(newAcct))
			})
		})

		Describe("Delete()", func() {
			It("deletes the account", func() {
				Expect(client.Delete(context.Background(), newAcct.ID)).To(Succeed())

				acct, err := accountForID(client, newAcct.ID)
				Expect(err).NotTo(HaveOccurred())
				Expect(acct).To(BeNil())
			})
		})
	})

	Context("when accout does not exist", func() {
		id := "nonExistingID"
		Describe("Update()", func() {
			It("returns AccountNotFoundError", func() {
				acct := &Account{ID: id}
				Expect(client.Update(context.Background(), acct)).To(MatchError(&AccountNotFoundError{ID: id}))
			})
		})

		Describe("Delete()", func() {
			It("returns AccountNotFoundError", func() {
				Expect(client.Delete(context.Background(), id)).To(MatchError(&AccountNotFoundError{ID: id}))
			})
		})
	})
})

func accountForID(c *Client, accountID string) (*Account, error) {
	accts, err := c.Accounts(context.Background())
	if err != nil {
		return nil, err
	}
	for _, acct := range accts {
		if acct.ID == accountID {
			return acct, nil
		}
	}
	return nil, nil
}
