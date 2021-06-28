// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package themis implements the proof-of-stake-authority consensus engine.
package themis

import (
	"bytes"
	"errors"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"io"
	"math"
	"math/big"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
)

const (
	checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the database
	inmemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
	inmemorySignatures = 4096 // Number of recent block signatures to keep in memory

	wiggleTime = 500 * time.Millisecond // Random delay (per signer) to allow concurrent signers
	maxValidators = 21
)

// themis proof-of-authority protocol constants.
var (
	epochLength = uint64(30000) // Default number of blocks after which to checkpoint and reset the pending votes

	extraVanity = 32                     // Fixed number of extra-data prefix bytes reserved for signer vanity
	extraSeal   = crypto.SignatureLength // Fixed number of extra-data suffix bytes reserved for signer seal

	uncleHash = types.CalcUncleHash(nil) // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.

	diffInTurn = big.NewInt(2) // Block difficulty for in-turn signatures
	diffNoTurn = big.NewInt(1) // Block difficulty for out-of-turn signatures
)

// System contract address.
var (
	validatorsContractName = "validators"
	punishContractName     = "punish"
	proposalContractName   = "proposal"
	validatorsContractAddr = common.HexToAddress("0x000000000000000000000000000000000000f000")
	punishContractAddr     = common.HexToAddress("0x000000000000000000000000000000000000f001")
	proposalAddr           = common.HexToAddress("0x000000000000000000000000000000000000f002")
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the validator vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte signature suffix missing")

	// errExtraValidators is returned if non-checkpoint block contain validator data in
	// their extra-data fields.
	errExtraValidators = errors.New("non-checkpoint block contains extra validator list")

	// errInvalidExtraValidators is returned if validator data in extra-data field is invalid.
	errInvalidExtraValidators = errors.New("Invalid extra validators in extra data field")

	// errInvalidCheckpointValidators is returned if a checkpoint block contains an
	// invalid list of validators (i.e. non divisible by 20 bytes).
	errInvalidCheckpointValidators = errors.New("invalid validator list on checkpoint block")

	// errMismatchingCheckpointValidators is returned if a checkpoint block contains a
	// list of validators different than the one the local node calculated.
	errMismatchingCheckpointValidators = errors.New("mismatching validator list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block neither 1 or 2.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// errWrongDifficulty is returned if the difficulty of a block doesn't match the
	// turn of the validator.
	errWrongDifficulty = errors.New("wrong difficulty")

	// errInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorizedValidator is returned if a header is signed by a non-authorized entity.
	errUnauthorizedValidator = errors.New("unauthorized validator")

	// errRecentlySigned is returned if a header is signed by an authorized entity
	// that already signed a header recently, thus is temporarily not allowed to.
	errRecentlySigned = errors.New("recently signed")

	// errInvalidValidatorLen is returned if validators length is zero or bigger than maxValidators.
	errInvalidValidatorsLength = errors.New("Invalid validators length")

	// errInvalidCoinbase is returned if the coinbase isn't the validator of the block.
	errInvalidCoinbase = errors.New("Invalid coin base")
)

// StateFn gets state by the state root hash.
type StateFn func(hash common.Hash) (*state.StateDB, error)

// ValidatorFn hashes and signs the data to be signed by a backing account.
type ValidatorFn func(validator accounts.Account, mimeType string, message []byte) ([]byte, error)

// ecrecover extracts the Ethereum account address from a signed header.
func ecrecover(header *types.Header, sigcache *lru.ARCCache) (common.Address, error) {
	// If the signature's already cached, return that
	hash := header.Hash()
	if address, known := sigcache.Get(hash); known {
		return address.(common.Address), nil
	}
	// Retrieve the signature from the header extra-data
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	signature := header.Extra[len(header.Extra)-extraSeal:]

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(SealHash(header).Bytes(), signature)
	if err != nil {
		return common.Address{}, err
	}
	var validator common.Address
	copy(validator[:], crypto.Keccak256(pubkey[1:])[12:])

	sigcache.Add(hash, validator)
	return validator, nil
}

// Themis is the proof-of-stake-authority consensus engine proposed to support the
// Ethereum testnet following the Ropsten attacks.
type Themis struct {
	chainConfig *params.ChainConfig    // ChainConfig to execute evm
	config      *params.ThemisConfig // Consensus engine configuration parameters
	db          ethdb.Database         // Database to store and retrieve snapshot checkpoints

	recents    *lru.ARCCache // Snapshots for recent block to speed up reorgs
	signatures *lru.ARCCache // Signatures of recent blocks to speed up mining

	proposals map[common.Address]bool // Current list of proposals we are pushing

	validator common.Address // Ethereum address of the signing key
	signFn    ValidatorFn    // Validator function to authorize hashes with
	lock      sync.RWMutex   // Protects the validator fields

	stateFn StateFn // Function to get state by state root

	abi map[string]abi.ABI // Interactive with system contracts

	// The fields below are for testing only
	fakeDiff bool // Skip difficulty verifications
}

// New creates a Themis proof-of-stake-authority consensus engine with the initial
// signers set to the ones provided by the user.
func New(chainConfig *params.ChainConfig, db ethdb.Database) *Themis {
	// Set any missing consensus parameters to their defaults
	conf := *chainConfig.Themis
	if conf.Epoch == 0 {
		conf.Epoch = epochLength
	}
	// Allocate the snapshot caches and create the engine
	recents, _ := lru.NewARC(inmemorySnapshots)
	signatures, _ := lru.NewARC(inmemorySignatures)

	abi := getInteractiveABI()

	return &Themis{
		chainConfig: chainConfig,
		config:      &conf,
		db:          db,
		recents:     recents,
		signatures:  signatures,
		proposals:   make(map[common.Address]bool),
		abi:         abi,
	}
}

// SetStateFn sets the function to get state.
func (t *Themis) SetStateFn(fn StateFn) {
	t.stateFn = fn
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (t *Themis) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (t *Themis) VerifyHeader(chain consensus.ChainHeaderReader, header *types.Header, seal bool) error {
	return t.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (t *Themis) VerifyHeaders(chain consensus.ChainHeaderReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := t.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (t *Themis) verifyHeader(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}
	number := header.Number.Uint64()

	// Don't waste time checking blocks from the future
	if header.Time > uint64(time.Now().Unix()) {
		return consensus.ErrFutureBlock
	}
	
	// Check that the extra-data contains the vanity, validators and signature
	if len(header.Extra) < extraVanity {
		return errMissingVanity
	}
	if len(header.Extra) < extraVanity+extraSeal {
		return errMissingSignature
	}
	// check extra data
	isEpoch := number%t.config.Epoch == 0

	// Ensure that the extra-data contains a validator list on checkpoint, but none otherwise
	validatorsBytes := len(header.Extra) - extraVanity - extraSeal
	if !isEpoch && validatorsBytes != 0 {
		return errExtraValidators
	}
	// Ensure that the validator bytes length is valid
	if isEpoch && validatorsBytes%common.AddressLength != 0 {
		return errExtraValidators
	}
	
	// Ensure that the mix digest is zero as we don't have fork protection currently
	if header.MixDigest != (common.Hash{}) {
		return errInvalidMixDigest
	}
	// Ensure that the block doesn't contain any uncles which are meaningless in PoA
	if header.UncleHash != uncleHash {
		return errInvalidUncleHash
	}
	// Ensure that the block's difficulty is meaningful (may not be correct at this point)
	if number > 0 && header.Difficulty == nil {
		return errInvalidDifficulty
	}
	// If all checks passed, validate any special fields for hard forks
	if err := misc.VerifyForkHashes(chain.Config(), header, false); err != nil {
		return err
	}
	// All basic checks passed, verify cascading fields
	return t.verifyCascadingFields(chain, header, parents)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (t *Themis) verifyCascadingFields(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time+t.config.Period > header.Time {
		return ErrInvalidTimestamp
	}
	// All basic checks passed, verify the seal and return
	return t.verifySeal(chain, header, parents)
}

// snapshot retrieves the authorization snapshot at a given point in time.
func (t *Themis) snapshot(chain consensus.ChainHeaderReader, number uint64, hash common.Hash, parents []*types.Header) (*Snapshot, error) {
	// Search for a snapshot in memory or on disk for checkpoints
	var (
		headers []*types.Header
		snap    *Snapshot
	)
	for snap == nil {
		// If an in-memory snapshot was found, use that
		if s, ok := t.recents.Get(hash); ok {
			snap = s.(*Snapshot)
			break
		}
		// If an on-disk checkpoint snapshot can be found, use that
		if number%checkpointInterval == 0 {
			if s, err := loadSnapshot(t.config, t.signatures, t.db, hash); err == nil {
				log.Trace("Loaded voting snapshot from disk", "number", number, "hash", hash)
				snap = s
				break
			}
		}
		// If we're at the genesis, snapshot the initial state. Alternatively if we're
		// at a checkpoint block without a parent (light client CHT), or we have piled
		// up more headers than allowed to be reorged (chain reinit from a freezer),
		// consider the checkpoint trusted and snapshot it.
		if number == 0 || (number%t.config.Epoch == 0 && (len(headers) > params.FullImmutabilityThreshold || chain.GetHeaderByNumber(number-1) == nil)) {
			checkpoint := chain.GetHeaderByNumber(number)
			if checkpoint != nil {
				hash := checkpoint.Hash()

				validators := make([]common.Address, (len(checkpoint.Extra)-extraVanity-extraSeal)/common.AddressLength)
				for i := 0; i < len(validators); i++ {
					copy(validators[i][:], checkpoint.Extra[extraVanity+i*common.AddressLength:])
				}
				snap = newSnapshot(t.config, t.signatures, number, hash, validators)
				if err := snap.store(t.db); err != nil {
					return nil, err
				}
				log.Info("Stored checkpoint snapshot to disk", "number", number, "hash", hash)
				break
			}
		}
		// No snapshot for this header, gather the header and move backward
		var header *types.Header
		if len(parents) > 0 {
			// If we have explicit parents, pick from there (enforced)
			header = parents[len(parents)-1]
			if header.Hash() != hash || header.Number.Uint64() != number {
				return nil, consensus.ErrUnknownAncestor
			}
			parents = parents[:len(parents)-1]
		} else {
			// No explicit parents (or no more left), reach out to the database
			header = chain.GetHeader(hash, number)
			if header == nil {
				return nil, consensus.ErrUnknownAncestor
			}
		}
		headers = append(headers, header)
		number, hash = number-1, header.ParentHash
	}
	// Previous snapshot found, apply any pending headers on top of it
	for i := 0; i < len(headers)/2; i++ {
		headers[i], headers[len(headers)-1-i] = headers[len(headers)-1-i], headers[i]
	}
	snap, err := snap.apply(headers, chain, parents)
	if err != nil {
		return nil, err
	}
	t.recents.Add(snap.Hash, snap)

	// If we've generated a new checkpoint snapshot, save to disk
	if snap.Number%checkpointInterval == 0 && len(headers) > 0 {
		if err = snap.store(t.db); err != nil {
			return nil, err
		}
		log.Trace("Stored voting snapshot to disk", "number", snap.Number, "hash", snap.Hash)
	}
	return snap, err
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (t *Themis) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (t *Themis) VerifySeal(chain consensus.ChainHeaderReader, header *types.Header) error {
	return t.verifySeal(chain, header, nil)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (t *Themis) verifySeal(chain consensus.ChainHeaderReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// Retrieve the snapshot needed to verify this header and cache it
	snap, err := t.snapshot(chain, number-1, header.ParentHash, parents)
	if err != nil {
		return err
	}

	// Resolve the authorization key and check against validators
	signer, err := ecrecover(header, t.signatures)
	if err != nil {
		return err
	}
	if signer != header.Coinbase {
		return errInvalidCoinbase
	}
	
	if _, ok := snap.Validators[signer]; !ok {
		return errUnauthorizedValidator
	}
	
	for seen, recent := range snap.Recents {
		if recent == signer {
			// Validator is among recents, only fail if the current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); seen > number-limit {
				return errRecentlySigned
			}
		}
	}
	// Ensure that the difficulty corresponds to the turn-ness of the signer
	if !t.fakeDiff {
		inturn := snap.inturn(header.Number.Uint64(), signer)
		if inturn && header.Difficulty.Cmp(diffInTurn) != 0 {
			return errWrongDifficulty
		}
		if !inturn && header.Difficulty.Cmp(diffNoTurn) != 0 {
			return errWrongDifficulty
		}
	}
	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (t *Themis) Prepare(chain consensus.ChainHeaderReader, header *types.Header) error {
	// If the block isn't a checkpoint, cast a random vote (good enough for now)
	header.Coinbase = t.validator
	header.Nonce = types.BlockNonce{}

	number := header.Number.Uint64()
	// Assemble the voting snapshot to check which votes make sense
	snap, err := t.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}

	// Set the correct difficulty
	header.Difficulty = calcDifficulty(snap, t.validator)

	// Ensure the extra data has all its components
	if len(header.Extra) < extraVanity {
		header.Extra = append(header.Extra, bytes.Repeat([]byte{0x00}, extraVanity-len(header.Extra))...)
	}
	header.Extra = header.Extra[:extraVanity]

	if number%t.config.Epoch == 0 {
		newSortedValidators, err := t.getTopValidators(chain, header)
		if err != nil {
			return err
		}

		for _, validator := range newSortedValidators {
			header.Extra = append(header.Extra, validator.Bytes()...)
		}
	}
	header.Extra = append(header.Extra, make([]byte, extraSeal)...)

	// Mix digest is reserved for now, set to empty
	header.MixDigest = common.Hash{}

	// Ensure the timestamp has the correct delay
	parent := chain.GetHeader(header.ParentHash, number-1)
	if parent == nil {
		return consensus.ErrUnknownAncestor
	}
	header.Time = parent.Time + t.config.Period
	if header.Time < uint64(time.Now().Unix()) {
		header.Time = uint64(time.Now().Unix())
	}
	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given.
func (t *Themis) Finalize(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header) error {
	// Initialize all system contracts at block 1.
	if header.Number.Cmp(common.Big1) == 0 {
		if err := t.initializeSystemContracts(chain, header, state); err != nil {
			log.Error("Initialize system contracts failed", "err", err)
			return err
		}
	}

	if header.Difficulty.Cmp(diffInTurn) != 0 {
		if err := t.tryPunishValidator(chain, header, state); err != nil {
			return err
		}
	}

	// execute block reward tx.
	if len(txs) > 0 {
		if err := t.trySendBlockReward(chain, header, state); err != nil {
			return err
		}
	}

	// accumulate static rewards for mining a block
	t.tryAccumulateStaticRewards(state, header)

	// do epoch thing at the end, because it will update active validators
	if header.Number.Uint64()%t.config.Epoch == 0 {
		newValidators, err := t.doSomethingAtEpoch(chain, header, state)
		if err != nil {
			return err
		}

		validatorsBytes := make([]byte, len(newValidators)*common.AddressLength)
		for i, validator := range newValidators {
			copy(validatorsBytes[i*common.AddressLength:], validator.Bytes())
		}

		extraSuffix := len(header.Extra) - extraSeal
		if !bytes.Equal(header.Extra[extraVanity:extraSuffix], validatorsBytes) {
			return errInvalidExtraValidators
		}
	}

	// No block rewards in PoA, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	return nil
}

// FinalizeAndAssemble implements consensus.Engine, ensuring no uncles are set,
// nor block rewards given, and returns the final block.
func (t *Themis) FinalizeAndAssemble(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Initialize all system contracts at block 1.
	if header.Number.Cmp(common.Big1) == 0 {
		if err := t.initializeSystemContracts(chain, header, state); err != nil {
			panic(err)
		}
	}

	// punish validator if necessary
	if header.Difficulty.Cmp(diffInTurn) != 0 {
		if err := t.tryPunishValidator(chain, header, state); err != nil {
			panic(err)
		}
	}

	// deposit block fee reward if any tx exists.
	if len(txs) > 0 {
		if err := t.trySendBlockReward(chain, header, state); err != nil {
			panic(err)
		}
	}
	// accumulate static rewards for mining a block
	t.tryAccumulateStaticRewards(state, header)

	// do epoch thing at the end, because it will update active validators
	if header.Number.Uint64()%t.config.Epoch == 0 {
		if _, err := t.doSomethingAtEpoch(chain, header, state); err != nil {
			panic(err)
		}
	}
	
	// No block rewards in PoA, so the state remains as is and uncles are dropped
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	header.UncleHash = types.CalcUncleHash(nil)

	// Assemble and return the final block for sealing
	return types.NewBlock(header, txs, nil, receipts, new(trie.Trie)), nil
}

func (t *Themis) tryAccumulateStaticRewards(state *state.StateDB, header *types.Header)  {
	// static rewards for a mining block
	staticBlockReward := consensus.ThemisBlockReward
	remainStaticRewards := state.GetBalance(consensus.MintAddress)
	log.Info("Remain rewards = ", remainStaticRewards.String())
	if staticBlockReward.Cmp(remainStaticRewards) <= 0 {
		log.Info("coinbase="+header.Coinbase.String()+"; static rewards="+staticBlockReward.String())
		state.AddBalance(header.Coinbase, staticBlockReward)
		state.SubBalance(consensus.MintAddress, staticBlockReward)
	}
}

func (t *Themis) trySendBlockReward(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	// fee distribute for validators
	fee := state.GetBalance(consensus.FeeRecorder)
	if fee.Cmp(common.Big0) <= 0 {
		return nil
	}

	// Miner will send tx to deposit block fees to contract, add to his balance first.
	state.AddBalance(header.Coinbase, fee)
	// reset fee
	state.SetBalance(consensus.FeeRecorder, common.Big0)

	method := "distributeBlockReward"
	data, err := t.abi[validatorsContractName].Pack(method)
	if err != nil {
		log.Error("Can't pack data for distributeBlockReward", "err", err)
		return err
	}

	nonce := state.GetNonce(header.Coinbase)
	msg := types.NewMessage(header.Coinbase, &validatorsContractAddr, nonce, fee, math.MaxUint64, new(big.Int), data, true)

	if _, err := executeMsg(msg, state, header, newChainContext(chain, t), t.chainConfig); err != nil {
		return err
	}

	return nil
}

func (t *Themis) tryPunishValidator(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	number := header.Number.Uint64()
	snap, err := t.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	validators := snap.validators()
	outTurnValidator := validators[number%uint64(len(validators))]
	// check signed recently or not
	signedRecently := false
	for _, recent := range snap.Recents {
		if recent == outTurnValidator {
			signedRecently = true
			break
		}
	}
	if !signedRecently {
		if err := t.punishValidator(outTurnValidator, chain, header, state); err != nil {
			return err
		}
	}

	return nil
}

func (t *Themis) doSomethingAtEpoch(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) ([]common.Address, error) {
	newSortedValidators, err := t.getTopValidators(chain, header)
	if err != nil {
		return []common.Address{}, err
	}

	// update contract new validators if new set exists
	if err := t.updateValidators(newSortedValidators, chain, header, state); err != nil {
		return []common.Address{}, err
	}
	//  decrease validator missed blocks counter at epoch
	if err := t.decreaseMissedBlocksCounter(chain, header, state); err != nil {
		return []common.Address{}, err
	}

	return newSortedValidators, nil
}

// initializeSystemContracts initializes all system contracts.
func (t *Themis) initializeSystemContracts(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	snap, err := t.snapshot(chain, 0, header.ParentHash, nil)
	if err != nil {
		return err
	}

	genesisValidators := snap.validators()
	if len(genesisValidators) == 0 || len(genesisValidators) > maxValidators {
		return errInvalidValidatorsLength
	}

	method := "initialize"
	contracts := []struct {
		addr    common.Address
		packFun func() ([]byte, error)
	}{
		{validatorsContractAddr, func() ([]byte, error) {
			return t.abi[validatorsContractName].Pack(method, genesisValidators)
		}},
		{punishContractAddr, func() ([]byte, error) { return t.abi[punishContractName].Pack(method) }},
		{proposalAddr, func() ([]byte, error) { return t.abi[proposalContractName].Pack(method, genesisValidators) }},
	}

	for _, contract := range contracts {
		data, err := contract.packFun()
		if err != nil {
			return err
		}

		nonce := state.GetNonce(header.Coinbase)
		msg := types.NewMessage(header.Coinbase, &contract.addr, nonce, new(big.Int), math.MaxUint64, new(big.Int), data, true)

		if _, err := executeMsg(msg, state, header, newChainContext(chain, t), t.chainConfig); err != nil {
			return err
		}
	}

	return nil
}

// call this at epoch block to get top validators based on the state of epoch block - 1
func (t *Themis) getTopValidators(chain consensus.ChainHeaderReader, header *types.Header) ([]common.Address, error) {
	parent := chain.GetHeader(header.ParentHash, header.Number.Uint64()-1)
	if parent == nil {
		return []common.Address{}, consensus.ErrUnknownAncestor
	}
	statedb, err := t.stateFn(parent.Root)
	if err != nil {
		return []common.Address{}, err
	}

	method := "getTopValidators"
	data, err := t.abi[validatorsContractName].Pack(method)
	if err != nil {
		log.Error("Can't pack data for getTopValidators", "error", err)
		return []common.Address{}, err
	}

	msg := types.NewMessage(header.Coinbase, &validatorsContractAddr, 0, new(big.Int), math.MaxUint64, new(big.Int), data, false)

	// use parent
	result, err := executeMsg(msg, statedb, parent, newChainContext(chain, t), t.chainConfig)
	if err != nil {
		return []common.Address{}, err
	}

	// unpack data
	ret, err := t.abi[validatorsContractName].Unpack(method, result)
	if err != nil {
		return []common.Address{}, err
	}
	if len(ret) != 1 {
		return []common.Address{}, errors.New("Invalid params length")
	}
	validators, ok := ret[0].([]common.Address)
	if !ok {
		return []common.Address{}, errors.New("Invalid validators format")
	}
	sort.Sort(validatorsAscending(validators))
	return validators, err
}

func (t *Themis) updateValidators(vals []common.Address, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	// method
	method := "updateActiveValidatorSet"
	data, err := t.abi[validatorsContractName].Pack(method, vals, new(big.Int).SetUint64(t.config.Epoch))
	if err != nil {
		log.Error("Can't pack data for updateActiveValidatorSet", "error", err)
		return err
	}

	log.Info("update validators:", vals)
	// call contract
	nonce := state.GetNonce(header.Coinbase)
	msg := types.NewMessage(header.Coinbase, &validatorsContractAddr, nonce, new(big.Int), math.MaxUint64, new(big.Int), data, true)
	if _, err := executeMsg(msg, state, header, newChainContext(chain, t), t.chainConfig); err != nil {
		log.Error("Can't update validators to contract", "err", err)
		return err
	}

	return nil
}

func (t *Themis) punishValidator(val common.Address, chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	// method
	method := "punish"
	data, err := t.abi[punishContractName].Pack(method, val)
	if err != nil {
		log.Error("Can't pack data for punish", "error", err)
		return err
	}

	// call contract
	nonce := state.GetNonce(header.Coinbase)
	msg := types.NewMessage(header.Coinbase, &punishContractAddr, nonce, new(big.Int), math.MaxUint64, new(big.Int), data, true)
	if _, err := executeMsg(msg, state, header, newChainContext(chain, t), t.chainConfig); err != nil {
		log.Error("Can't punish validator", "err", err)
		return err
	}

	return nil
}

func (t *Themis) decreaseMissedBlocksCounter(chain consensus.ChainHeaderReader, header *types.Header, state *state.StateDB) error {
	// method
	method := "decreaseMissedBlocksCounter"
	data, err := t.abi[punishContractName].Pack(method, new(big.Int).SetUint64(t.config.Epoch))
	if err != nil {
		log.Error("Can't pack data for decreaseMissedBlocksCounter", "error", err)
		return err
	}

	// call contract
	nonce := state.GetNonce(header.Coinbase)
	msg := types.NewMessage(header.Coinbase, &punishContractAddr, nonce, new(big.Int), math.MaxUint64, new(big.Int), data, true)
	if _, err := executeMsg(msg, state, header, newChainContext(chain, t), t.chainConfig); err != nil {
		log.Error("Can't decrease missed blocks counter for validator", "err", err)
		return err
	}

	return nil
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (t *Themis) Authorize(validator common.Address, signFn ValidatorFn) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.validator = validator
	t.signFn = signFn
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (t *Themis) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}
	// For 0-period chains, refuse to seal empty blocks (no reward but would spin sealing)
	if t.config.Period == 0 && len(block.Transactions()) == 0 {
		log.Info("Sealing paused, waiting for transactions")
		return nil
	}
	// Don't hold the signer fields for the entire sealing procedure
	t.lock.RLock()
	validator, signFn := t.validator, t.signFn
	t.lock.RUnlock()

	// Bail out if we're unauthorized to sign a block
	snap, err := t.snapshot(chain, number-1, header.ParentHash, nil)
	if err != nil {
		return err
	}
	if _, authorized := snap.Validators[validator]; !authorized {
		return errUnauthorizedValidator
	}
	// If we're amongst the recent signers, wait for the next block
	for seen, recent := range snap.Recents {
		if recent == validator {
			// Signer is among recents, only wait if the current block doesn't shift it out
			if limit := uint64(len(snap.Validators)/2 + 1); number < limit || seen > number-limit {
				log.Info("Signed recently, must wait for others")
				return nil
			}
		}
	}
	// Sweet, the protocol permits us to sign the block, wait for our time
	delay := time.Unix(int64(header.Time), 0).Sub(time.Now()) // nolint: gosimple
	if header.Difficulty.Cmp(diffNoTurn) == 0 {
		// It's not our turn explicitly to sign, delay it a bit
		wiggle := time.Duration(len(snap.Validators)/2+1) * wiggleTime
		delay += time.Duration(rand.Int63n(int64(wiggle)))

		log.Trace("Out-of-turn signing requested", "wiggle", common.PrettyDuration(wiggle))
	}
	// Sign all the things!
	sighash, err := signFn(accounts.Account{Address: validator}, accounts.MimetypeThemis, ThemisRLP(header))
	if err != nil {
		return err
	}
	copy(header.Extra[len(header.Extra)-extraSeal:], sighash)
	// Wait until sealing is terminated or delay timeout.
	log.Trace("Waiting for slot to sign and propagate", "delay", common.PrettyDuration(delay))
	go func() {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		select {
		case results <- block.WithSeal(header):
		default:
			log.Warn("Sealing result is not read by miner", "sealhash", SealHash(header))
		}
	}()

	return nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have:
// * DIFF_NOTURN(2) if BLOCK_NUMBER % validator_COUNT != validator_INDEX
// * DIFF_INTURN(1) if BLOCK_NUMBER % validator_COUNT == validator_INDEX
func (t *Themis) CalcDifficulty(chain consensus.ChainHeaderReader, time uint64, parent *types.Header) *big.Int {
	snap, err := t.snapshot(chain, parent.Number.Uint64(), parent.Hash(), nil)
	if err != nil {
		return nil
	}
	return calcDifficulty(snap, t.validator)
}

func calcDifficulty(snap *Snapshot, validator common.Address) *big.Int {
	if snap.inturn(snap.Number+1, validator) {
		return new(big.Int).Set(diffInTurn)
	}
	return new(big.Int).Set(diffNoTurn)
}

// SealHash returns the hash of a block prior to it being sealed.
func (t *Themis) SealHash(header *types.Header) common.Hash {
	return SealHash(header)
}

// Close implements consensus.Engine. It's a noop for clique as there are no background threads.
func (t *Themis) Close() error {
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (t *Themis) APIs(chain consensus.ChainHeaderReader) []rpc.API {
	return []rpc.API{{
		Namespace: "themis",
		Version:   "1.0",
		Service:   &API{chain: chain, themis: t},
		Public:    false,
	}}
}

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	encodeSigHeader(hasher, header)
	hasher.Sum(hash[:0])
	return hash
}

// ThemisRLP returns the rlp bytes which needs to be signed for the proof-of-authority
// sealing. The RLP to sign consists of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func ThemisRLP(header *types.Header) []byte {
	b := new(bytes.Buffer)
	encodeSigHeader(b, header)
	return b.Bytes()
}

func encodeSigHeader(w io.Writer, header *types.Header) {
	err := rlp.Encode(w, []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra[:len(header.Extra)-crypto.SignatureLength], // Yes, this will panic if extra is too short
		header.MixDigest,
		header.Nonce,
	})
	if err != nil {
		panic("can't encode: " + err.Error())
	}
}
