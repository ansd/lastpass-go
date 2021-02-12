package integration_test

import (
	"context"

	. "github.com/ansd/lastpass-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Integration", func() {
	When("account exists", func() {
		var account *Account

		BeforeEach(func() {
			account = &Account{
				ID:       "",
				Name:     "test site",
				Username: "test user",
				Password: "test pwd",
				URL:      "https://testURL",
				Group:    "test group",
				Notes:    "test notes",
			}
			Expect(client.Add(context.Background(), account)).To(Succeed())
		})

		AfterEach(func() {
			Expect(client.Delete(context.Background(), account.ID)).To(Succeed())
		})

		Describe("Add()", func() {
			It("adds account", func() {
				Expect(accountForID(client, account.ID)).To(Equal(account))
			})
		})

		Describe("Accounts()", func() {
			It("lists accounts", func() {
				Expect(client.Accounts(context.Background())).To(ContainElement(account))
			})
		})

		Describe("Update()", func() {
			It("updates account", func() {
				account.Username = "updated user"
				account.Password = "updated pwd"
				Expect(client.Update(context.Background(), account)).To(Succeed())
				Expect(accountForID(client, account.ID)).To(Equal(account))
			})
		})

		Describe("Delete()", func() {
			It("deletes account", func() {
				Expect(client.Delete(context.Background(), account.ID)).To(Succeed())
				Expect(accountForID(client, account.ID)).To(BeNil())
			})
		})
	})

	When("accout does not exist", func() {
		const id string = "nonExistingID"
		Describe("Update()", func() {
			It("returns AccountNotFoundError", func() {
				account := &Account{ID: id}
				Expect(client.Update(context.Background(), account)).To(MatchError(&AccountNotFoundError{ID: id}))
			})
		})

		Describe("Delete()", func() {
			It("returns AccountNotFoundError", func() {
				Expect(client.Delete(context.Background(), id)).To(MatchError(&AccountNotFoundError{ID: id}))
			})
		})
	})
})

func accountForID(c *Client, accountID string) *Account {
	accounts, err := c.Accounts(context.Background())
	Expect(err).NotTo(HaveOccurred())
	for _, a := range accounts {
		if a.ID == accountID {
			return a
		}
	}
	return nil
}
