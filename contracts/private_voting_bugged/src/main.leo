// ============================================================================
// Private Voting Contract (BUGGED Version)
//
// Contains 3 deliberate bugs at the INSTRUCTION level:
//
//   Bug #1: cast_vote sets voted_ballot.owner = self.caller instead of
//           my_ballot.owner — OWNER LEADS TO PRIVACY LEAK.
//           The symbolic executor finds: owner field is present and looks valid
//           (self.caller is an address), but LeoZap's invariant checker with
//           owner_integrity enabled may flag this because the output owner
//           differs from the expected pattern.
//
//   Bug #2: register_voter ignores the election parameter and hardcodes 0field.
//           Voters can only register for election 0 regardless of input.
//           Symbolic executor finds: the election_id field value doesn't match
//           what was passed in (caught via invariant assertions).
//
//   Bug #3: cast_vote_for_election uses assert_eq(election, election) — a
//           TAUTOLOGY. Any election value passes the check. The correct code
//           should be: assert_eq(my_ballot.election_id, election).
//           Symbolic executor: this always passes (both sides resolve to same
//           register value), but the ZK verification path would catch it
//           because leo run would execute the WRONG logic.
//
// These bugs demonstrate LeoZap's ability to find:
//   - Privacy violations (owner integrity)
//   - Parameter misuse (ignored arguments)
//   - Incorrect logic (tautological checks)
// ============================================================================

program private_voting.aleo {
    @noupgrade
    constructor() {}

    mapping tally: field => u64;

    record ballot {
        owner: address,
        election_id: field,
        voted: bool,
    }

    // Bug #2: election parameter is accepted but HARDCODED to 0field
    fn register_voter(voter: address, election: field) -> ballot {
        return ballot {
            owner: voter,
            election_id: 0field,
            voted: false,
        };
    }

    // Bug #1: Uses self.caller instead of my_ballot.owner
    fn cast_vote(
        my_ballot: ballot,
        candidate: field,
    ) -> (ballot, Final) {
        assert(!my_ballot.voted);

        // BUG #1: self.caller instead of my_ballot.owner — PRIVACY LEAK
        let voted_ballot: ballot = ballot {
            owner: self.caller,
            election_id: my_ballot.election_id,
            voted: true,
        };

        return (
            voted_ballot,
            final { finalize_cast_vote(candidate); },
        );
    }

    // Bug #3: assert_eq(election, election) is a TAUTOLOGY — always passes
    fn cast_vote_for_election(
        my_ballot: ballot,
        election: field,
        candidate: field,
    ) -> (ballot, Final) {
        assert(!my_ballot.voted);
        // BUG #3: Should be: assert_eq(my_ballot.election_id, election);
        // This tautology means ANY election passes the check.
        assert_eq(election, election);

        // Also has Bug #1
        let voted_ballot: ballot = ballot {
            owner: self.caller,
            election_id: election,
            voted: true,
        };

        return (
            voted_ballot,
            final { finalize_cast_vote(candidate); },
        );
    }
}

final fn finalize_cast_vote(candidate: field) {
    let current: u64 = Mapping::get_or_use(tally, candidate, 0u64);
    Mapping::set(tally, candidate, current + 1u64);
}
