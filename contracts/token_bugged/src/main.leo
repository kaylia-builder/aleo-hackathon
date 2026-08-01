program token.aleo {
    @noupgrade
    constructor() {}

    mapping account: address => u64;

    record token {
        owner: address,
        amount: u64,
    }

    fn mint_public(public receiver: address, public amount: u64) -> Final {
        return final { finalize_mint_public(receiver, amount); };
    }

    fn mint_private(receiver: address, amount: u64) -> token {
        return token { owner: receiver, amount: amount };
    }

    fn transfer_public(public receiver: address, public amount: u64) -> Final {
        let caller = self.caller;
        return final { finalize_transfer_public(caller, receiver, amount); };
    }

    fn transfer_private(sender: token, receiver: address, amount: u64) -> (token, token) {
        // BUG #1: addition instead of subtraction — inflation vulnerability!
        // Sender keeps their tokens AND gains more, doubling their balance.
        let difference: u64 = sender.amount + amount;
        let remaining: token = token { owner: sender.owner, amount: difference };
        let transferred: token = token { owner: receiver, amount: amount };
        return (remaining, transferred);
    }

    fn transfer_private_to_public(
        sender: token,
        public receiver: address,
        public amount: u64,
    ) -> (token, Final) {
        let difference: u64 = sender.amount - amount;
        let remaining: token = token { owner: sender.owner, amount: difference };
        return (
            remaining,
            final { finalize_transfer_priv2pub(receiver, amount); },
        );
    }

    fn transfer_public_to_private(public receiver: address, public amount: u64) -> (token, Final) {
        let transferred: token = token { owner: receiver, amount: amount };
        let caller = self.caller;
        return (
            transferred,
            final { finalize_transfer_pub2priv(caller, amount); },
        );
    }
}

final fn finalize_mint_public(receiver: address, amount: u64) {
    let current_amount: u64 = Mapping::get_or_use(account, receiver, 0u64);
    Mapping::set(account, receiver, current_amount + amount);
}

final fn finalize_transfer_public(sender: address, receiver: address, amount: u64) {
    let sender_amount: u64 = Mapping::get_or_use(account, sender, 0u64);
    Mapping::set(account, sender, sender_amount - amount);
    let receiver_amount: u64 = Mapping::get_or_use(account, receiver, 0u64);
    Mapping::set(account, receiver, receiver_amount + amount);
}

final fn finalize_transfer_priv2pub(receiver: address, amount: u64) {
    let current_amount: u64 = Mapping::get_or_use(account, receiver, 0u64);
    Mapping::set(account, receiver, current_amount + amount);
}

final fn finalize_transfer_pub2priv(sender: address, amount: u64) {
    let current_amount: u64 = Mapping::get_or_use(account, sender, 0u64);
    Mapping::set(account, sender, current_amount - amount);
}