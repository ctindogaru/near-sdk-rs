//! Based on [`openzeppelin/access`](https://github.com/OpenZeppelin/openzeppelin-contracts/tree/master/contracts/access) files.

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{env, require, AccountId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type RoleId = [u8; 32];

/// Contract module which provides a basic access control mechanism, where
/// there is an account (an [`Self::owner`]) that can be granted exclusive access to
/// specific functions.
///
/// By default, the owner account will be the [one that deploys](env::predecessor_account_id())
/// the contract. This can later be changed with [`Self::transfer_ownership()`].
///
/// This module makes available the modifier [`Self::only_owner()`], which can be applied to your
///  functions to restrict their use to the owner.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct Ownable {
    pub owner: Option<AccountId>,
}

impl Ownable {
    /// Initializes the contract setting
    /// the [`predecessor account`](env::predecessor_account_id())
    /// as the initial [`Self::owner`].
    pub fn new() -> Self {
        Self { owner: Some(env::predecessor_account_id()) }
    }

    /// Returns the address of the current [`Self::owner`].  
    /// Panics if it has no owner.
    pub fn owner(&self) -> Option<AccountId> {
        self.owner.clone()
    }

    /// Has no effect if called by the owner.
    /// Panics otherwise.
    pub fn only_owner(&self) {
        require!(
            Some(env::predecessor_account_id()) == self.owner,
            "Ownable: caller is not the owner"
        );
    }

    /// Permanently leaves the contract without an [`Self::owner`].  
    /// Can only be called by the current owner.
    ///
    /// # WARNING
    ///
    /// Renouncing ownership will leave the contract without an owner,
    /// thereby removing any functionality that is only available to the owner.  
    /// ie. future calls into [`Self::only_owner()`] will always panic.
    pub fn permanently_renounce_ownership(&mut self) {
        self.only_owner();
        self.owner = None;
    }

    /// Tranfers [ownership](Self::owner) of the contract to a new account `new_owner`.  
    /// Can only be called by the current owner.
    pub fn transfer_ownership(&mut self, new_owner: AccountId) {
        self.only_owner();
        self.owner = Some(new_owner);
    }
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct RoleData {
    // TODO: consider using HashSet,
    // in case the bool as false has no particular use
    pub members: HashMap<AccountId, bool>,
    pub admin_role: RoleId,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct AccessControl {
    pub roles: HashMap<RoleId, RoleData>,
    /// Default [admin role](RoleData::admin_role) for newly created roles.
    pub default_admin_role: RoleId,
}

impl AccessControl {
    pub fn new() -> Self {
        Self { roles: HashMap::new(), default_admin_role: RoleId::default() }
    }

    /// Returns `true` if `account` has been granted `role`.  
    /// Otherwise, and on [missing `role`](Self::roles) or [missing `account`](RoleData::members), returns `false`.
    pub fn has_role(&self, role: &RoleId, account: &AccountId) -> bool {
        self.roles
            .get(role)
            .and_then(|role_data| role_data.members.get(account).cloned())
            .unwrap_or(false)
    }

    /// Has no effect if `account` [has been granted](RoleData::members) `role`.  
    /// Otherwise, and on [missing `role`](Self::roles) or [missing `account`](RoleData::members),
    /// panics with a standard message.
    ///
    /// TODO: check this:  
    /// The format of the panic message is given by the following regular expression:  
    /// `/^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/`
    ///
    /// Uses [`Self::has_role()`] internally.
    pub fn check_role(&self, role: &RoleId, account: &AccountId) {
        if !self.has_role(role, account) {
            env::panic_str(
                format!("AccessControl: account {} is missing role {:?}", *account, *role).as_str(),
            )
        }
    }

    /// Has no effect if the [`predecessor account`](env::predecessor_account_id())
    /// has a specific `role`.  
    /// Otherwise, and on [missing `role`](Self::roles) or [missing `account`](RoleData::members),
    /// panics with a standard message including the required role.
    ///
    /// TODO: check this:  
    /// The format of the panic message is given by the following regular expression:  
    /// `/^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/`
    ///
    /// Uses [`Self::check_role()`] internally.
    pub fn only_role(&self, role: &RoleId) {
        self.check_role(role, &env::predecessor_account_id());
    }

    /// Returns the [`admin role`](RoleData::admin_role) that controls `role`.  
    /// Othewise on [missing `role`](Self::roles), returns [`Self::default_admin_role`].
    ///
    /// See also [`Self::grant_role()`] and [`Self::revoke_role()`].  
    /// See [`Self::set_role_admin()`] to change a role's [admin role](RoleData::admin_role).
    pub fn get_role_admin(&self, role: &RoleId) -> RoleId {
        self.roles
            .get(role)
            .map(|role_data| role_data.admin_role)
            .unwrap_or(self.default_admin_role)
    }

    /// Grants [`role` to `account`](RoleData::members).
    ///
    /// Requirements:
    ///
    /// - The [`role`](Self::roles) must exist.
    /// - The caller must have the `role`'s [admin role](RoleData::admin_role).
    ///
    /// Uses [`Self::only_role()`] and then [`Self::internal_setup_role()`] internally.  
    ///
    /// See also [`Self::revoke_role()`] for the opposite effect.
    pub fn grant_role(&mut self, role: RoleId, account: AccountId) {
        self.only_role(&self.get_role_admin(&role));
        self.internal_setup_role(role, account);
    }

    /// Grants [`role` to `account`](RoleData::members),
    /// [creating the `role`](Self::roles) if necessary.  
    /// If `account` was already disabled in `role`, it is simply enabled.
    ///
    /// # Warning
    ///
    /// This method should only be called from the constructor when setting
    /// up the initial roles for the system.
    ///
    /// Using this function in any other way is effectively circumventing the admin
    /// system imposed by [`AccessControll`].
    fn internal_setup_role(&mut self, role: RoleId, account: AccountId) {
        use std::collections::hash_map::Entry;
        match self.roles.entry(role) {
            // `role` did not exist
            Entry::Vacant(role_entry) => {
                // creates a new role, while also adding `account` as a member of it.
                let mut members = HashMap::new();
                members.insert(account, true);
                role_entry.insert(RoleData { members, admin_role: self.default_admin_role });
            }

            // `role` already existed
            Entry::Occupied(mut role_entry) => {
                match role_entry.get_mut().members.entry(account) {
                    // `account` had no previous setup
                    Entry::Vacant(member_entry) => {
                        member_entry.insert(true);
                    }
                    // `account` had a previous setup, but replaces with a `true`.
                    Entry::Occupied(mut member_entry) => {
                        *member_entry.get_mut() = true;
                    }
                }
            }
        }
    }

    /// Revokes [`role` from `account`](RoleData::members).
    ///
    /// Requirements:
    ///
    /// - The [`role`](Self::roles) must exist.
    /// - The caller must have the `role`'s [admin role](RoleData::admin_role).
    ///
    /// Uses [`Self::only_role()`] internally.  
    ///
    /// See also [`Self::grant_role()`] for the opposite effect.
    pub fn revoke_role(&mut self, role: RoleId, account: AccountId) {
        self.only_role(&self.get_role_admin(&role));
        self.internal_revoke_role(role, account);
    }

    /// Revokes [`role` from `account`](RoleData::members).
    ///
    /// Has no effect if the [`role`](Self::roles) does not exist,
    /// or if the [`account`](RoleData::members) is not a member for that `role`,
    /// or if the `account` was already disabled.
    fn internal_revoke_role(&mut self, role: RoleId, account: AccountId) {
        use std::collections::hash_map::Entry;
        match self.roles.entry(role) {
            // `role` exists
            Entry::Occupied(mut role_entry) => {
                match role_entry.get_mut().members.entry(account) {
                    // `account` is a member, update status
                    Entry::Occupied(mut member_entry) => {
                        *member_entry.get_mut() = false;
                    }

                    // `account` isn't a member, no action needed
                    Entry::Vacant(_) => {}
                }
            }

            // `role` inexistent, no action needed
            Entry::Vacant(_) => {}
        }
    }

    /// Revokes [`role` from](RoleData::members) the [predecessor's `account`](env::predecessor_account_id()).  
    /// Has no effect if the [`role`](Self::roles) does not exist, or if the [`account`
    /// is not enabled](RoleData::members) for that `role`.
    ///
    /// This method's purpose is to provide a mechanism for `account`s to purposefuly
    /// [lose their own privileges](RoleData::members), such as when they are compromised
    /// (eg. when a trusted device is misplaced).
    ///
    /// Requirements:
    ///
    /// - The `account` must be the [predecessor account](env::predecessor_account_id()).
    ///
    /// See also [`Self::grant_role()`] and [`Self::revoke_role()`] for other management of
    /// roles.
    pub fn renounce_role(&mut self, role: RoleId, account: AccountId) {
        require!(
            account == env::predecessor_account_id(),
            "AccessControl: can only renounce roles for self"
        );
        self.internal_revoke_role(role, account);
    }

    /// Sets `admin_role` as `role`'s [admin role](RoleData::admin_role),
    /// [creating the `role`](Self::roles) if necessary.  
    ///
    /// # Warning
    ///
    /// There are no further verifications about the caller.
    fn internal_set_role_admin(&mut self, role: RoleId, admin_role: RoleId) {
        use std::collections::hash_map::Entry;
        match self.roles.entry(role) {
            // `role` does not exist
            Entry::Vacant(role_entry) => {
                // creates the role with the correct admin
                role_entry.insert(RoleData { members: HashMap::new(), admin_role });
            }

            // role exists
            Entry::Occupied(mut role_entry) => {
                // changes the admin of that role
                role_entry.get_mut().admin_role = admin_role;
            }
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    use super::*;

    fn get_context(predecessor_account_id: AccountId) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .signer_account_id(predecessor_account_id.clone())
            .predecessor_account_id(predecessor_account_id);
        builder
    }

    #[test]
    fn test_new() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let ownable = Ownable::new();
        assert_eq!(ownable.owner(), Some(accounts(1)));
    }

    #[test]
    fn test_only_owner_success() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let ownable = Ownable::new();
        ownable.only_owner();
    }

    #[test]
    #[should_panic(expected = "Ownable: caller is not the owner")]
    fn test_only_owner_fail() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let ownable = Ownable::new();
        let context = get_context(accounts(2));
        testing_env!(context.build());
        ownable.only_owner();
    }

    #[test]
    fn test_renounce_ownership() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let mut ownable = Ownable::new();
        assert_eq!(ownable.owner(), Some(accounts(1)));
        ownable.permanently_renounce_ownership();
        assert_eq!(ownable.owner(), None);
    }

    #[test]
    fn test_transfer_ownership() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let mut ownable = Ownable::new();
        assert_eq!(ownable.owner(), Some(accounts(1)));
        ownable.transfer_ownership(accounts(2));
        assert_eq!(ownable.owner(), Some(accounts(2)));
    }

    #[test]
    fn test_ac_new() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        AccessControl::new();
    }

    #[test]
    fn test_ac_has_role() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let ac = AccessControl::new();
        assert_eq!(false, ac.has_role(&[1; 32], &accounts(2)));
    }

    #[test]
    #[should_panic(
        expected = "AccessControl: account charlie is missing role [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]"
    )]
    fn test_ac_check_role() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let ac = AccessControl::new();
        ac.check_role(&[1; 32], &accounts(2));
    }

    #[test]
    #[should_panic(
        expected = "AccessControl: account bob is missing role [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]"
    )]
    fn test_ac_only_role() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let ac = AccessControl::new();
        ac.only_role(&[1; 32]);
    }

    #[test]
    fn test_ac_set_and_get_role_admin() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let mut ac = AccessControl::new();
        let default_admin_role = [0; 32];
        let role = [1; 32];
        let admin_role = [2; 32];
        ac.internal_set_role_admin(role, admin_role);
        assert_eq!(admin_role, ac.get_role_admin(&role));
        assert_eq!(default_admin_role, ac.get_role_admin(&admin_role));
    }

    #[test]
    fn test_grant_role() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let mut ac = AccessControl::new();
        let role = [1; 32];
        let role_admin = [2; 32];
        ac.internal_set_role_admin(role, role_admin);
        ac.internal_setup_role(role_admin, accounts(1));
        ac.grant_role(role, accounts(1));
        assert_eq!(true, ac.has_role(&role, &accounts(1)));
        assert_eq!(true, ac.has_role(&role, &accounts(1)));
    }

    #[test]
    #[should_panic(expected = "AccessControl: can only renounce roles for self")]
    fn test_renounce_role_fail() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let mut ac = AccessControl::new();
        ac.renounce_role([1; 32], accounts(2));
    }

    #[test]
    fn test_renounce_role_success() {
        let context = get_context(accounts(1));
        testing_env!(context.build());
        let mut ac = AccessControl::new();
        let role = [1; 32];
        let role_admin = [2; 32];
        ac.internal_set_role_admin(role, role_admin);
        ac.internal_setup_role(role_admin, accounts(1));
        ac.grant_role(role, accounts(1));
        assert_eq!(true, ac.has_role(&role, &accounts(1)));
        ac.renounce_role(role, accounts(1));
        assert_eq!(false, ac.has_role(&role, &accounts(1)));
    }
}
