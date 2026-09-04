-- What a create or an import leaves behind belongs to the key it produced. The v2 interfaces keep no state between
-- calls, so nothing here tracks an operation: these are facts about a key, kept the way a connector without a
-- database keeps them, as attributes of the key in its own technology.
--
-- A key destroyed takes them with it, which is what a caller repeating an operation for a key that is gone should
-- find: a record outliving its key would answer a repeat with a key that no longer exists.
--
-- A key created through the v1 interfaces states none of them. A null is distinct from every other null, so the two
-- halves of one pair fit the constraints while those keys stay unconstrained.

-- The identifier a caller repeats a lost creation under, and the terms it was asked on. The identifier is the
-- platform's own and is not scoped to a token, so the same one arriving for another token is a different request
-- wearing it rather than a creation of its own.
alter table if exists key_data
    add column key_creation_id varchar(256);

alter table if exists key_data
    add constraint key_data_key_creation_id_key
    unique (key_creation_id, type);

alter table if exists key_data
    add column creation_fingerprint varchar(64);

-- The identity the platform holds for an imported key, which it never reads back from a response.
alter table if exists key_data
    add column platform_reference uuid;

alter table if exists key_data
    add constraint key_data_platform_reference_key
    unique (platform_reference, type);

-- The identifier a caller repeats a lost import under, and the terms it was asked on. The platform protects the
-- material afresh every time, so the envelope cannot decide whether two imports ask for the same thing.
alter table if exists key_data
    add column key_import_id varchar(256);

alter table if exists key_data
    add constraint key_data_key_import_id_key
    unique (key_import_id, type);

alter table if exists key_data
    add column import_fingerprint varchar(64);

-- Whether a key may ever leave the token. Only an import states it, so a key that never stated it cannot leave, and
-- every key that already exists is such a key.
alter table if exists key_data
    add column exportable boolean not null default false;

-- A token has always been addressed by name, and the interfaces before this refused to create a second one with a
-- name already taken. Stating it here is what settles two requests addressing the same token at once: the database
-- refuses the loser, rather than both creating one. That request cannot then read the winning row itself, since its
-- failed insert leaves the persistence context unusable, so it is answered as retryable and the caller reaches the
-- winning row by repeating it.
alter table if exists token_instance
    add constraint token_instance_name_key
    unique (name);
