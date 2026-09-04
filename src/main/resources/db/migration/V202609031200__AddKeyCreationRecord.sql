create table key_creation_record
(
    uuid uuid not null,
    creation_id varchar(256) not null,
    token_instance_uuid uuid not null,
    request_fingerprint varchar(64) not null,
    public_key_uuid uuid not null,
    private_key_uuid uuid not null,
    created_at timestamp not null,
    primary key (uuid)
);

alter table if exists key_creation_record
    add constraint key_creation_record_creation_id_key
    unique (creation_id);

alter table if exists key_creation_record
    add constraint key_creation_record_to_token_instance_uuid_key
    foreign key (token_instance_uuid)
    references token_instance (uuid)
    on update no action on delete cascade;

-- A token has always been addressed by name, and the interfaces before this refused to create a second one with a
-- name already taken. Stating it here is what lets two requests addressing the same token at once recover: the loser
-- of the race is refused by the database and reads the row the winner wrote, rather than both creating one.
alter table if exists token_instance
    add constraint token_instance_name_key
    unique (name);
