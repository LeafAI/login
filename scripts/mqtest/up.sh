#!/bin/sh
# Starts a throwaway RocketMQ (NameServer, one Broker) and the RocketMQ Dashboard on 127.0.0.1, with login switched on, for the
# tests of the rocketmq driver. Prints the variable the tests read. Stop it with: docker rm -f rmq-dash rmq-broker rmq-ns
# The accounts are the fixture's, fixed and public: these servers hold nothing and listen on the loopback only.
#   admin  / admin-pass-1   (an administrator)
#   viewer / viewer-pass-1  (a normal user)
# Dashboard 2.0.1 is what the production Dashboard looks like (an AngularJS front end that logs in with
# POST /login/login.do?username=...&password=..., with no CSRF token).
set -eu
PORT="${SECURL_TEST_ROCKETMQ_PORT:-28080}"
VERSION="${SECURL_TEST_DASHBOARD_VERSION:-2.0.1}"
here="$(cd "$(dirname "$0")" && pwd)"
docker rm -f rmq-dash rmq-broker rmq-ns >/dev/null 2>&1 || true
docker network rm rmqnet >/dev/null 2>&1 || true
docker network create rmqnet >/dev/null
docker run -d --name rmq-ns --network rmqnet -m 400m -e JAVA_OPT_EXT="-Xms128m -Xmx256m -Xmn96m" apache/rocketmq:5.3.1 sh mqnamesrv >/dev/null
sleep 8
docker run -d --name rmq-broker --network rmqnet -m 900m \
  -e JAVA_OPT_EXT="-Xms256m -Xmx512m -Xmn128m -XX:MaxDirectMemorySize=128m" apache/rocketmq:5.3.1 \
  sh -c 'printf "brokerIP1=rmq-broker\nbrokerName=broker-a\nautoCreateTopicEnable=true\n" > /tmp/b.conf; exec sh mqbroker -n rmq-ns:9876 -c /tmp/b.conf' >/dev/null
i=0
until docker logs rmq-broker 2>&1 | grep -q "boot success"; do
  i=$((i + 1)); [ "$i" -gt 40 ] && { echo "broker did not start" >&2; exit 1; }; sleep 3
done
docker run -d --name rmq-dash --network rmqnet -p "127.0.0.1:$PORT:8080" -m 700m \
  -e JAVA_OPTS="-Xms128m -Xmx384m -Drocketmq.namesrv.addr=rmq-ns:9876 -Drocketmq.config.loginRequired=true -Drocketmq.config.dataPath=/tmp/rocketmq-console/data" \
  -v "$here/data:/tmp/rocketmq-console/data:ro" "apacherocketmq/rocketmq-dashboard:$VERSION" >/dev/null
i=0
until curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$PORT/login/check.query"; do
  i=$((i + 1)); [ "$i" -gt 40 ] && { echo "dashboard did not start" >&2; exit 1; }; sleep 3
done
echo "export SECURL_TEST_ROCKETMQ=127.0.0.1:$PORT"
