package integration_test

import (
	"context"
	"strconv"
	"time"

	. "github.com/ansd/lastpass-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
)

var _ = Describe("Integration", func() {
	When("account exists", func() {
		var acct *Account
		var creationTimestamp int64

		BeforeEach(func() {
			creationTimestamp = time.Now().Unix()
			acct = &Account{
				ID:       "",
				Name:     "test site",
				Username: "test user",
				Password: "test pwd",
				URL:      "https://testURL",
				Group:    "test group",
				Notes:    "test notes",
			}
			Expect(client.Add(context.Background(), acct)).To(Succeed())
		})

		AfterEach(func() {
			Expect(client.Delete(context.Background(), acct.ID)).To(Succeed())
		})

		Describe("Add()", func() {
			It("adds account", func() {
				actual := accountForID(client, acct.ID)
				Expect(actual).To(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"ID":        Equal(acct.ID),
						"Name":      Equal(acct.Name),
						"Username":  Equal(acct.Username),
						"Password":  Equal(acct.Password),
						"URL":       Equal(acct.URL),
						"Group":     Equal(acct.Group),
						"Notes":     Equal(acct.Notes),
						"LastTouch": Equal("0"), // means "never used"
					})))
				lastModified, err := strconv.ParseUint(actual.LastModifiedGMT, 10, 32)
				Expect(err).ToNot(HaveOccurred())
				Expect(lastModified).To(BeNumerically("~", creationTimestamp, 60))
			})
		})

		Describe("Accounts()", func() {
			It("lists accounts", func() {
				Expect(client.Accounts(context.Background())).To(
					ContainElement(PointTo(MatchAllFields(Fields{
						"ID":              Equal(acct.ID),
						"Name":            Equal(acct.Name),
						"Username":        Equal(acct.Username),
						"Password":        Equal(acct.Password),
						"URL":             Equal(acct.URL),
						"Group":           Equal(acct.Group),
						"Notes":           Equal(acct.Notes),
						"LastModifiedGMT": Not(BeEmpty()),
						"LastTouch":       Equal("0"), // means "never used"
					}))))
			})
		})

		Describe("Update()", func() {
			It("updates account", func() {
				acct.Username = "updated user"
				acct.Password = "updated pwd"
				Expect(client.Update(context.Background(), acct)).To(Succeed())
				updated := accountForID(client, acct.ID)
				Expect(updated).To(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"ID":       Equal(acct.ID),
						"Name":     Equal(acct.Name),
						"Username": Equal(acct.Username),
						"Password": Equal(acct.Password),
						"URL":      Equal(acct.URL),
						"Group":    Equal(acct.Group),
						"Notes":    Equal(acct.Notes),
					})))
				lastModified, err := strconv.ParseUint(updated.LastModifiedGMT, 10, 32)
				Expect(err).ToNot(HaveOccurred())
				Expect(lastModified).To(BeNumerically("~", creationTimestamp, 60))

				lastTouch, err := strconv.ParseUint(updated.LastTouch, 10, 32)
				Expect(err).ToNot(HaveOccurred())
				// lastTouch is not in GMT.
				// Expect it to be within 12 hours offset range from GMT.
				Expect(lastTouch).To(BeNumerically("~", creationTimestamp, 60*60*12))
			})
		})

		Describe("Delete()", func() {
			It("deletes account", func() {
				Expect(client.Delete(context.Background(), acct.ID)).To(Succeed())
				Expect(accountForID(client, acct.ID)).To(BeNil())
			})
		})
	})

	When("accout does not exist", func() {
		const id string = "nonExistingID"
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
