-- Fixture for the database integration tests; see postgres.sql. Run as root against a throwaway MySQL server whose
-- MYSQL_DATABASE is appdb. Accounts: rw (everything on appdb) and ro (SELECT only), each with "<name>-pass-1".
CREATE USER IF NOT EXISTS 'rw'@'%' IDENTIFIED BY 'rw-pass-1';
CREATE USER IF NOT EXISTS 'ro'@'%' IDENTIFIED BY 'ro-pass-1';
GRANT ALL ON appdb.* TO 'rw'@'%';
GRANT SELECT ON appdb.* TO 'ro'@'%';
USE appdb;
-- The same 50 rows as postgres.sql. The tests of internal/dbexec rebuild the table themselves, but the end-to-end tests of
-- internal/mcpserver use what is here, so a table without rows made them fail on a fresh server and pass on a used one.
DROP TABLE IF EXISTS items;
CREATE TABLE items (id int auto_increment primary key, name varchar(100) not null, qty int not null default 0);
INSERT INTO items(name, qty) WITH RECURSIVE n(g) AS (SELECT 1 UNION ALL SELECT g+1 FROM n WHERE g<50) SELECT CONCAT('item', g), g FROM n;
