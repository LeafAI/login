#!/bin/sh
# Starts a throwaway PostgreSQL and MySQL on 127.0.0.1 for the database integration tests, loads the fixture, and prints
# the environment variables the tests read. Stop them with: docker rm -f securl-test-pg securl-test-my
# The passwords are the fixture's, fixed and public: these servers hold nothing and listen on the loopback only.
set -eu
PG_PORT="${SECURL_TEST_PG_PORT:-45432}"
MY_PORT="${SECURL_TEST_MYSQL_PORT:-43306}"
here="$(cd "$(dirname "$0")" && pwd)"
docker rm -f securl-test-pg securl-test-my >/dev/null 2>&1 || true
docker run -d --name securl-test-pg -e POSTGRES_PASSWORD=rootpw -p "127.0.0.1:$PG_PORT:5432" postgres:17-alpine >/dev/null
docker run -d --name securl-test-my -e MYSQL_ROOT_PASSWORD=rootpw -e MYSQL_DATABASE=appdb -p "127.0.0.1:$MY_PORT:3306" mysql:8.4 >/dev/null
i=0
until docker exec securl-test-pg pg_isready -U postgres >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "postgres did not start" >&2; exit 1; }; sleep 2
done
i=0
# The MySQL image restarts once after its init scripts: wait until it answers over TCP, not just on its socket.
until docker exec securl-test-my mysqladmin ping -h 127.0.0.1 -uroot -prootpw --silent >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 90 ] && { echo "mysql did not start" >&2; exit 1; }; sleep 2
done
sleep 3
docker exec -i securl-test-pg psql -U postgres -v ON_ERROR_STOP=1 <"$here/postgres.sql" >/dev/null
docker exec -i securl-test-my mysql -uroot -prootpw appdb <"$here/mysql.sql" >/dev/null 2>&1
echo "export SECURL_TEST_PG=127.0.0.1:$PG_PORT SECURL_TEST_MYSQL=127.0.0.1:$MY_PORT"
