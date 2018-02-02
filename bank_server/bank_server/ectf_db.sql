drop table if exists cards;
create table cards (account_name text not null unique, card_id text not null unique, balance integer, bank_aes_key text, nonce integer, pin_hash text, salt text, primary key (account_name, card_id));
create table atms (atm_id text primary key, num_bills integer, bank_aes_key text, nonce integer);
