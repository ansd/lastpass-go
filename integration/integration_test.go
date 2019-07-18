package integration_test

import (
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
			addedID, err := client.Add(
				newAcct.Name,
				newAcct.Username,
				newAcct.Password,
				newAcct.URL,
				newAcct.Group,
				newAcct.Notes,
			)
			Expect(err).NotTo(HaveOccurred())
			newAcct.ID = addedID
		})

		AfterEach(func() {
			Expect(client.Delete(newAcct.ID)).To(Succeed())
		})

		Describe("Add", func() {
			It("adds the account", func() {
				acct, err := client.Account(newAcct.ID)
				Expect(err).NotTo(HaveOccurred())
				Expect(acct).To(Equal(newAcct))
			})
		})

		Describe("Update", func() {
			It("updates the account", func() {
				newAcct.Username = "updated user"
				newAcct.Password = "updated pwd"
				Expect(client.Update(newAcct)).To(Succeed())

				acct, err := client.Account(newAcct.ID)
				Expect(err).NotTo(HaveOccurred())
				Expect(acct).To(Equal(newAcct))
			})
		})

		Describe("Delete", func() {
			It("deletes the account", func() {
				Expect(client.Delete(newAcct.ID)).To(Succeed())

				acct, err := client.Account(newAcct.ID)
				Expect(err).NotTo(HaveOccurred())
				Expect(acct).To(BeNil())
			})
		})
	})

	Context("when accout does not exist", func() {
		Describe("Update", func() {
			It("errors", func() {
				acct := &Account{ID: "nonExistingID"}
				Expect(client.Update(acct)).To(MatchError(
					"could not find account with ID=nonExistingID"))
			})
		})

		Describe("Delete", func() {
			It("errors", func() {
				Expect(client.Delete("nonExistingID")).To(MatchError(
					"could not find account with ID=nonExistingID"))
			})
		})
	})
})
