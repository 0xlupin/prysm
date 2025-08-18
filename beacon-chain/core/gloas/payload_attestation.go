package gloas

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/OffchainLabs/prysm/v7/beacon-chain/core/helpers"
	"github.com/OffchainLabs/prysm/v7/beacon-chain/core/signing"
	"github.com/OffchainLabs/prysm/v7/beacon-chain/state"
	fieldparams "github.com/OffchainLabs/prysm/v7/config/fieldparams"
	"github.com/OffchainLabs/prysm/v7/config/params"
	consensus_types "github.com/OffchainLabs/prysm/v7/consensus-types"
	"github.com/OffchainLabs/prysm/v7/consensus-types/interfaces"
	"github.com/OffchainLabs/prysm/v7/consensus-types/primitives"
	"github.com/OffchainLabs/prysm/v7/crypto/bls"
	"github.com/OffchainLabs/prysm/v7/crypto/hash"
	"github.com/OffchainLabs/prysm/v7/encoding/bytesutil"
	eth "github.com/OffchainLabs/prysm/v7/proto/prysm/v1alpha1"
	"github.com/OffchainLabs/prysm/v7/time/slots"
	"github.com/pkg/errors"
)

// ProcessPayloadAttestations validates payload attestations in a block body.
// Spec v1.6.1 (pseudocode):
// process_payload_attestation(state: BeaconState, payload_attestation: PayloadAttestation):
//
//	data = payload_attestation.data
//	assert data.beacon_block_root == state.latest_block_header.parent_root
//	assert data.slot + 1 == state.slot
//	indexed = get_indexed_payload_attestation(state, data.slot, payload_attestation)
//	assert is_valid_indexed_payload_attestation(state, indexed)
func ProcessPayloadAttestations(ctx context.Context, st state.BeaconState, body interfaces.ReadOnlyBeaconBlockBody) error {
	atts, err := body.PayloadAttestations()
	if err != nil {
		return errors.Wrap(err, "failed to get payload attestations from block body")
	}
	if len(atts) == 0 {
		return nil
	}

	header := st.LatestBlockHeader()
	for i, att := range atts {
		data := att.Data
		if !bytes.Equal(data.BeaconBlockRoot, header.ParentRoot) {
			return fmt.Errorf("payload attestation %d has wrong parent: got %x want %x", i, data.BeaconBlockRoot, header.ParentRoot)
		}
		if data.Slot+1 != st.Slot() {
			return fmt.Errorf("payload attestation %d has wrong slot: got %d want %d", i, data.Slot+1, st.Slot())
		}

		indexed, err := indexedPayloadAttestation(ctx, st, data.Slot, att)
		if err != nil {
			return errors.Wrapf(err, "payload attestation %d failed to convert to indexed form", i)
		}
		if err := validIndexedPayloadAttestation(st, indexed); err != nil {
			return errors.Wrapf(err, "payload attestation %d failed to verify indexed form", i)
		}
	}
	return nil
}

// indexedPayloadAttestation converts a payload attestation into its indexed form
func indexedPayloadAttestation(ctx context.Context, st state.ReadOnlyBeaconState, slot primitives.Slot, att *eth.PayloadAttestation) (*consensus_types.IndexedPayloadAttestation, error) {
	committee, err := payloadTimelinessCommittee(ctx, st, slot)
	if err != nil {
		return nil, err
	}
	indices := make([]primitives.ValidatorIndex, 0, len(committee))
	for i, idx := range committee {
		if att.AggregationBits.BitAt(uint64(i)) {
			indices = append(indices, idx)
		}
	}
	slices.Sort(indices)

	return &consensus_types.IndexedPayloadAttestation{
		AttestingIndices: indices,
		Data:             att.Data,
		Signature:        att.Signature,
	}, nil
}

// payloadTimelinessCommittee returns the payload timeliness committee for a given slot for the state.
// Spec v1.6.1 (pseudocode):
// get_ptc(state: BeaconState, slot: Slot) -> Vector[ValidatorIndex, PTC_SIZE]:
//
//	epoch = compute_epoch_at_slot(slot)
//	seed = hash(get_seed(state, epoch, DOMAIN_PTC_ATTESTER) + uint_to_bytes(slot))
//	indices = []
//	committees_per_slot = get_committee_count_per_slot(state, epoch)
//	for i in range(committees_per_slot):
//	  committee = get_beacon_committee(state, slot, CommitteeIndex(i))
//	  indices.extend(committee)
//	return compute_balance_weighted_selection(state, indices, seed, size=PTC_SIZE, shuffle_indices=False)
func payloadTimelinessCommittee(ctx context.Context, st state.ReadOnlyBeaconState, slot primitives.Slot) ([]primitives.ValidatorIndex, error) {
	epoch := slots.ToEpoch(slot)
	seed, err := ptcSeed(st, epoch, slot)
	if err != nil {
		return nil, err
	}

	valCount := uint64(st.NumValidators())
	committeesPerSlot := helpers.SlotCommitteeCount(valCount)
	out := make([]primitives.ValidatorIndex, 0, committeesPerSlot*(valCount/committeesPerSlot))

	for i := primitives.CommitteeIndex(0); i < primitives.CommitteeIndex(committeesPerSlot); i++ {
		committee, err := helpers.BeaconCommitteeFromState(ctx, st, slot, i)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get beacon committee %d", i)
		}
		out = append(out, committee...)
	}

	return balanceWeightedSelection(st, out, seed, fieldparams.PTCSize)
}

// ptcSeed computes the seed for the payload timeliness committee.
func ptcSeed(st state.ReadOnlyBeaconState, epoch primitives.Epoch, slot primitives.Slot) ([32]byte, error) {
	seed, err := helpers.Seed(st, epoch, params.BeaconConfig().DomainPTCAttester)
	if err != nil {
		return [32]byte{}, err
	}
	return hash.Hash(append(seed[:], bytesutil.Bytes8(uint64(slot))...)), nil
}

// balanceWeightedSelection selects a balance-weighted subset of input candidates
// Spec v1.6.1 (pseudocode):
// compute_balance_weighted_selection(state, indices, seed, size, shuffle_indices):
//
//	total = len(indices); selected = []; i = 0
//	while len(selected) < size:
//	  next = i % total
//	  if shuffle_indices: next = compute_shuffled_index(next, total, seed)
//	  if compute_balance_weighted_acceptance(state, indices[next], seed, i):
//	    selected.append(indices[next])
//	  i += 1
func balanceWeightedSelection(st state.ReadOnlyBeaconState, candidates []primitives.ValidatorIndex, seed [32]byte, count uint64) ([]primitives.ValidatorIndex, error) {
	if len(candidates) == 0 {
		return nil, errors.New("no candidates for balance weighted selection")
	}

	hashFunc := hash.CustomSHA256Hasher()
	var buf [40]byte
	copy(buf[:], seed[:])
	maxBalance := params.BeaconConfig().MaxEffectiveBalanceElectra

	selected := make([]primitives.ValidatorIndex, 0, count)
	total := uint64(len(candidates))
	for i := uint64(0); uint64(len(selected)) < count; i++ {
		idx := candidates[i%total]
		ok, err := validatorAccepted(st, idx, buf[:], hashFunc, maxBalance, i)
		if err != nil {
			return nil, err
		}
		if ok {
			selected = append(selected, idx)
		}
	}
	return selected, nil
}

// validatorAccepted determines if a validator is accepted based on its effective balance.
// Spec v1.6.1 (pseudocode):
// compute_balance_weighted_acceptance(state, index, seed, i):
//
//	MAX_RANDOM_VALUE = 2**16 - 1
//	random_bytes = hash(seed + uint_to_bytes(i // 16))
//	offset = i % 16 * 2
//	random_value = bytes_to_uint64(random_bytes[offset:offset+2])
//	effective_balance = state.validators[index].effective_balance
//	return effective_balance * MAX_RANDOM_VALUE >= MAX_EFFECTIVE_BALANCE_ELECTRA * random_value
func validatorAccepted(st state.ReadOnlyBeaconState, idx primitives.ValidatorIndex, seedBuf []byte, hashFunc func([]byte) [32]byte, maxBalance uint64, round uint64) (bool, error) {
	// Reuse the seed buffer by overwriting the last 8 bytes with the round counter.
	binary.LittleEndian.PutUint64(seedBuf[len(seedBuf)-8:], round/16)
	random := hashFunc(seedBuf)
	offset := (round % 16) * 2
	rnd := uint64(binary.LittleEndian.Uint16(random[offset:]))

	val, err := st.ValidatorAtIndex(idx)
	if err != nil {
		return false, errors.Wrapf(err, "validator %d", idx)
	}

	return val.EffectiveBalance*fieldparams.MaxRandomValueElectra >= maxBalance*rnd, nil
}

// validIndexedPayloadAttestation verifies the signature of an indexed payload attestation.
// Spec v1.6.1 (pseudocode):
// is_valid_indexed_payload_attestation(state: BeaconState, indexed_payload_attestation: IndexedPayloadAttestation) -> bool:
//
//	indices = indexed_payload_attestation.attesting_indices
//	return len(indices) > 0 and indices == sorted(indices) and
//	  bls.FastAggregateVerify(
//	    [state.validators[i].pubkey for i in indices],
//	    compute_signing_root(indexed_payload_attestation.data, get_domain(state, DOMAIN_PTC_ATTESTER, None)),
//	    indexed_payload_attestation.signature,
//	  )
func validIndexedPayloadAttestation(st state.ReadOnlyBeaconState, att *consensus_types.IndexedPayloadAttestation) error {
	indices := att.AttestingIndices
	if len(indices) == 0 || !slices.IsSorted(indices) {
		return errors.New("attesting indices empty or unsorted")
	}

	pubkeys := make([]bls.PublicKey, len(indices))
	for i, idx := range indices {
		val, err := st.ValidatorAtIndexReadOnly(idx)
		if err != nil {
			return errors.Wrapf(err, "validator %d", idx)
		}
		keyBytes := val.PublicKey()
		key, err := bls.PublicKeyFromBytes(keyBytes[:])
		if err != nil {
			return errors.Wrapf(err, "pubkey %d", idx)
		}
		pubkeys[i] = key
	}

	domain, err := signing.Domain(st.Fork(), slots.ToEpoch(st.Slot()), params.BeaconConfig().DomainPTCAttester, st.GenesisValidatorsRoot())
	if err != nil {
		return err
	}
	root, err := signing.ComputeSigningRoot(att.Data, domain)
	if err != nil {
		return err
	}
	sig, err := bls.SignatureFromBytes(att.Signature)
	if err != nil {
		return err
	}

	if !sig.FastAggregateVerify(pubkeys, root) {
		return errors.New("invalid signature")
	}
	return nil
}
