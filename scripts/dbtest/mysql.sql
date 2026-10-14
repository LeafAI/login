-- Fixture for the database integration tests; see postgres.sql. Run as root against a throwaway MySQL server whose
-- MYSQL_DATABASE is appdb. Accounts: rw (everything on appdb) and ro (SELECT only), each with "<name>-pass-1".
CREATE USER IF NOT EXISTS 'rw'@'%' IDENTIFIED BY 'rw-pass-1';
CREATE USER IF NOT EXISTS 'ro'@'%' IDENTIFIED BY 'ro-pass-1';
GRANT ALL ON appdb.* TO 'rw'@'%';
GRANT SELECT ON appdb.* TO 'ro'@'%';
USE appdb;
CREATE TABLE IF NOT EXISTS items (id int auto_increment primary key, name varchar(100) not null, qty int not null default 0);
