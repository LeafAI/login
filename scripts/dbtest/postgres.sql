-- Fixture for the database integration tests (internal/dbexec, internal/mcpserver). Run it as the superuser of a
-- throwaway PostgreSQL server; scripts/dbtest/up.sh does that for a local container, and CI does it for its service.
-- Accounts: rw (everything on appdb) and ro (SELECT only), each with the password "<name>-pass-1".
CREATE DATABASE appdb;
\c appdb
CREATE ROLE rw LOGIN PASSWORD 'rw-pass-1';
CREATE ROLE ro LOGIN PASSWORD 'ro-pass-1';
GRANT ALL ON DATABASE appdb TO rw;
GRANT CONNECT ON DATABASE appdb TO ro;
GRANT ALL ON SCHEMA public TO rw;
GRANT USAGE ON SCHEMA public TO ro;
-- The tests rebuild items themselves (dbexec_test.go: reset), so they do not depend on what is here.
CREATE TABLE items (id serial primary key, name text not null, qty int not null default 0);
INSERT INTO items(name, qty) SELECT 'item' || g, g FROM generate_series(1, 50) g;
GRANT ALL ON ALL TABLES IN SCHEMA public TO rw;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO rw;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ro;
