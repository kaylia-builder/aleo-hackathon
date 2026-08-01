// ============================================================================
// Private Voting Contract (Safe Version)
//
// A privacy-preserving voting system built on Aleo:
// - Voters receive a private `ballot` record proving eligibility
// - Votes are cast privately — the ballot is consumed so no double-voting
// - Tally is public but individual votes are hidden by ZK proofs
//
// Invariants LeoZap can verify:
//   1. One vote per ballot (ballot is consumed in cast_vote)
//   2. Vote tally correctly increments by exactly 1
//   3. New ballot records preserve owner integrity
// ============================================================================

program private_voting.aleo {
    @noupgrade
    constructor() {}

    /// Public vote tally: candidate_id => vote_count
    mapping tally: field => u64;

    /// A private ballot record — proves a voter is eligible.
    /// The voter must consume this to cast their vote (prevents double-voting).
    record ballot {
        owner: address,
        election_id: field,
        voted: bool,
    }

    // ========================================================================
    // Admin: register a voter by issuing a ballot record
    // ========================================================================
    fn register_voter(voter: address, election: field) -> ballot {
        // Issue a fresh ballot to the voter
        return ballot {
            owner: voter,
            election_id: election,
            voted: false,
        };
    }

    // ========================================================================
    // Voter: cast a private vote
    //
    // The `ballot` input is consumed — its fields are used to construct
    // the output records. A new ballot with voted=true is returned as proof
    // of having voted (but cannot be reused since it's marked).
    // ========================================================================
    fn cast_vote(
        my_ballot: ballot,
        candidate: field,
    ) -> (ballot, Final) {
        // Consume the ballot: create a replacement marked as voted
        // Sanity check: the ballot must not already be used
        assert(!my_ballot.voted);

        let voted_ballot: ballot = ballot {
            owner: my_ballot.owner,
            election_id: my_ballot.election_id,
            voted: true,
        };

        // Schedule the public tally update
        return (
            voted_ballot,
            final { finalize_cast_vote(candidate); },
        );
    }

    // ========================================================================
    // Voter: cast a private vote with a different election_id
    // (demonstrates multi-election support)
    // ========================================================================
    fn cast_vote_for_election(
        my_ballot: ballot,
        election: field,
        candidate: field,
    ) -> (ballot, Final) {
        assert(!my_ballot.voted);
        // Verify this ballot is for the right election
        assert_eq(my_ballot.election_id, election);

        let voted_ballot: ballot = ballot {
            owner: my_ballot.owner,
            election_id: election,
            voted: true,
        };

        return (
            voted_ballot,
            final { finalize_cast_vote(candidate); },
        );
    }
}

// ============================================================================
// Finalize: update the public tally
// ============================================================================
final fn finalize_cast_vote(candidate: field) {
    let current: u64 = Mapping::get_or_use(tally, candidate, 0u64);
    Mapping::set(tally, candidate, current + 1u64);
}
