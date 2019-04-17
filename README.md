![GrinSwap logo](grinswap_logo.png)

## About

GrinSwap makes it easy for anyone to trade in and out of [Grin](https://github.com/mimblewimble/grin) trustlessly, without the need for a third party. It makes OTC deals a breeze, it introduces a privacy preserving method for buying and selling Grin, and it improves the fungibility and privacy of tokens and assets on the Bitcoin and Ethereum networks.

This is an open source project written in Rust, with development led by @jaspervdm, the creator of the first atomic swaps for [Grin <> ETH](https://medium.com/grinswap/first-grin-atomic-swap-a16b4cc19196) and [Grin <> BTC](https://www.youtube.com/watch?list=PLvgCPbagiHgqYdVUj-ylqhsXOifWrExiq&v=sT3vNycMxw4). 

## Donate
The work on this project is funded by the community, with support from Binance Labs and Gitcoin Grants. You can help support this effort by making a donation via the following methods:

* **GRIN** <br> [grinbox://gVuDf8U6CxjLfa6Wp93iG8jPFnbwuZbVkQuS4vPkatUayNB6u8uX](https://github.com/vault713/wallet713/blob/master/docs/usage.md#transacting-using-grinbox)

* **ETH / ERC-20** <br>Gitcoin matching grant: https://gitcoin.co/grants/96/grinswap-cross-chain-atomic-swaps-with-grin
  
* **BTC** <br> *Coming soon* 

## Development Roadmap

### Month 1

#### Goal
Lay foundation of Rust library. Flexible codebase that will be able to handle multiple cryptocurrencies

#### Development / Features
* [ ] Define the swap Slate and its intermediate states
* [ ] Define and API for handling swap Slates and progressing / cancelling
* [ ] Interface with Grin chain, creating 2-of-2 multisignature output with timelocked refund

#### QA/Testing
* [ ] Build test routines
* [ ] Obtain feedback from other developers to ensure cryptography and implementation are safe

#### Documentation
* [ ] Document each step in the swap, and the different API methods

### Month 2

#### Goal
Implement specific requirements for ETH and ERC-20 swaps.

#### Development / Features
* [ ] Improve smart contract for adaptor signature based swap, for base ETH and ERC-20
* [ ] Build ETH/ERC-20 specific steps in the swap library
* [ ] Investigate options to deploy the contract, such as Metamask
* [ ] Interface with the ETH chain to query status of the contract
  
#### QA/Testing
* [ ] Perform swap with new library
* [ ] Additional scrutiny from community

#### Documentation
* [ ] Update where needed

### Month 3

#### Goal
[wallet713](https://github.com/vault713/wallet713) integration

#### Development / Features
* [ ] Initiate swap with wallet713, display state, handle finalization/timeout
* [ ] Perform swap either by sending files or by using [Grinbox](https://github.com/vault713/grinbox)
* [ ] Bulletin board for sellers/buyers to find each other

#### QA/Testing
* [ ] Test with swaps over wallet713, mainnet swaps.
* [ ] Community testing

#### Documentation
* [ ] Update wallet713 documentation with new commands related to swaps

### Future work

* [ ] Add BTC Support
* [ ] Add Order matching / price discovery

## License
Apache License v2.0.