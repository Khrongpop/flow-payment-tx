package main

import (
	"context"
	"fmt"

	"github.com/onflow/cadence"
	"github.com/onflow/flow-go-sdk"
	"github.com/onflow/flow-go-sdk/access/http"
	"github.com/onflow/flow-go-sdk/crypto"
)

const (
	fungibleToken       = "0x9a0766d93b6608b7"
	flowToken           = "0x7e60df042a9c0868"
	senderAddressHex    = "0x76c8d4ee09d5654e"
	payerAddressHex     = "0x0eed2d5eba5c5a89"
	recipientAddressHex = "0x034739537b4097ba"
	senderPrivateKeyHex = "77a83a7fa47626c1fa6e662d0b83fb45c25e7d27060766aa8bebe445ff6dcd44"
	payerPrivateKeyHex  = "f6c7b03a79f4483bb1a8789c195939100fd3aafb958cb0ad69970fc3d80855ba"
)

func main() {
	// Single
	fmt.Println("Single Party, hex: ", singleParty())

	// Multiple
	// fmt.Println("Multiple Parties, hex: ", multipleParties())
}

func singleParty() string {
	ctx := context.Background()
	tx := flow.NewTransaction()

	script := getTransferScript(fungibleToken, flowToken)
	tx.SetScript([]byte(script))
	tx.SetGasLimit(100)

	// new flow client
	client, err := http.NewClient(http.TestnetHost)
	if err != nil {
		panic(err)
	}

	// get referecnce block
	latestBlock, err := client.GetLatestBlockHeader(ctx, true)
	if err != nil {
		panic(err)
	}
	tx.SetReferenceBlockID(latestBlock.ID)

	senderAccount, err := client.GetAccount(ctx, flow.HexToAddress(senderAddressHex))
	if err != nil {
		panic(err)
	}

	tx.SetProposalKey(senderAccount.Address, senderAccount.Keys[0].Index, senderAccount.Keys[0].SequenceNumber)
	tx.SetPayer(senderAccount.Address)
	tx.AddAuthorizer(senderAccount.Address)

	amount, err := cadence.NewUFix64("1.234")
	if err != nil {
		panic(err)
	}

	if err = tx.AddArgument(amount); err != nil {
		panic(err)
	}

	recipient := cadence.NewAddress(flow.HexToAddress(recipientAddressHex))

	err = tx.AddArgument(recipient)
	if err != nil {
		panic(err)
	}

	sigAlgo := crypto.ECDSA_P256
	hashAlgo := crypto.SHA3_256
	signer, err := newSigner(sigAlgo, hashAlgo, senderPrivateKeyHex)
	if err != nil {
		panic(err)
	}

	if err = tx.SignEnvelope(senderAccount.Address, senderAccount.Keys[0].Index, signer); err != nil {
		panic(err)
	}

	if err = client.SendTransaction(ctx, *tx); err != nil {
		panic(err)
	}

	return tx.ID().Hex()
}

func multipleParties() string {
	ctx := context.Background()
	tx := flow.NewTransaction()

	script := getTransferScript(fungibleToken, flowToken)
	tx.SetScript([]byte(script))
	tx.SetGasLimit(100)

	// new flow client
	client, err := http.NewClient(http.TestnetHost)
	if err != nil {
		panic(err)
	}

	// get referecnce block
	latestBlock, err := client.GetLatestBlockHeader(ctx, true)
	if err != nil {
		panic(err)
	}
	tx.SetReferenceBlockID(latestBlock.ID)

	senderAccount, err := client.GetAccount(ctx, flow.HexToAddress(senderAddressHex))
	if err != nil {
		panic(err)
	}

	tx.SetProposalKey(senderAccount.Address, senderAccount.Keys[0].Index, senderAccount.Keys[0].SequenceNumber)
	tx.SetPayer(flow.HexToAddress(payerAddressHex))
	tx.AddAuthorizer(senderAccount.Address)

	amount, err := cadence.NewUFix64("1.234")
	if err != nil {
		panic(err)
	}

	if err = tx.AddArgument(amount); err != nil {
		panic(err)
	}

	recipient := cadence.NewAddress(flow.HexToAddress(recipientAddressHex))

	err = tx.AddArgument(recipient)
	if err != nil {
		panic(err)
	}

	sigAlgo := crypto.ECDSA_P256
	hashAlgo := crypto.SHA3_256
	senderSigner, err := newSigner(sigAlgo, hashAlgo, senderPrivateKeyHex)
	if err != nil {
		panic(err)
	}

	payerSigner, err := newSigner(sigAlgo, hashAlgo, payerPrivateKeyHex)
	if err != nil {
		panic(err)
	}

	err = tx.SignPayload(senderAccount.Address, senderAccount.Keys[0].Index, senderSigner)
	if err != nil {
		panic(err)
	}

	if err = tx.SignEnvelope(flow.HexToAddress(payerAddressHex), 0, payerSigner); err != nil {
		panic(err)
	}

	if err = client.SendTransaction(ctx, *tx); err != nil {
		panic(err)
	}

	return tx.ID().Hex()
}

func newSigner(sigAlgo crypto.SignatureAlgorithm, hashAlgo crypto.HashAlgorithm, keyHex string) (crypto.Signer, error) {
	privateKey, err := crypto.DecodePrivateKeyHex(sigAlgo, keyHex)
	if err != nil {
		return nil, err
	}

	return crypto.NewInMemorySigner(privateKey, hashAlgo)
}

func getTransferScript(fungibleToken string, token string) string {
	return fmt.Sprintf(`
		import FungibleToken from %s
		import FlowToken from %s

		transaction(amount: UFix64, to: Address) {
		    // The Vault resource that holds the tokens that are being transferred
		    let sentVault: @FungibleToken.Vault

		    prepare(signer: AuthAccount) {
		        // Get a reference to the signer's stored vault
		        let vaultRef = signer.borrow<&FlowToken.Vault>(from: /storage/flowTokenVault)
					?? panic("Could not borrow reference to the owner's Vault!")
		        // Withdraw tokens from the signer's stored vault
		        self.sentVault <- vaultRef.withdraw(amount: amount)
		    }

		    execute {
		        // Get a reference to the recipient's Receiver
		        let receiverRef =  getAccount(to)
		            .getCapability(/public/flowTokenReceiver)
		            .borrow<&{FungibleToken.Receiver}>()
					?? panic("Could not borrow receiver reference to the recipient's Vault")
		        // Deposit the withdrawn tokens in the recipient's receiver
		        receiverRef.deposit(from: <-self.sentVault)
		    }
		}
	`, fungibleToken, token)
}
