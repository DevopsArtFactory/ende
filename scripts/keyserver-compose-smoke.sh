set -eu

go build -o /tmp/ende ./cmd/ende

ENDE=/tmp/ende
KEYSERVER="${ENDE_KEYSERVER_URL:-http://keyserver:8765}"

rm -rf /tmp/ende-compose
mkdir -p /tmp/ende-compose/alice /tmp/ende-compose/bob

ENDE_CONFIG_DIR=/tmp/ende-compose/alice "$ENDE" init --name alice --keyserver "$KEYSERVER"
ENDE_CONFIG_DIR=/tmp/ende-compose/alice "$ENDE" keyserver login --name alice --keyserver "$KEYSERVER" --access-token dev:alice
ENDE_CONFIG_DIR=/tmp/ende-compose/alice "$ENDE" keyserver publish --name alice --keyserver "$KEYSERVER"

ENDE_CONFIG_DIR=/tmp/ende-compose/bob "$ENDE" init --name bob --keyserver "$KEYSERVER"
ENDE_CONFIG_DIR=/tmp/ende-compose/bob "$ENDE" keyserver login --provider okta --name bob --keyserver "$KEYSERVER" --access-token dev:bob
ENDE_CONFIG_DIR=/tmp/ende-compose/bob "$ENDE" keyserver publish --name bob --keyserver "$KEYSERVER"

ENDE_CONFIG_DIR=/tmp/ende-compose/alice "$ENDE" peer fetch bob --keyserver "$KEYSERVER"
ENDE_CONFIG_DIR=/tmp/ende-compose/bob "$ENDE" peer fetch alice --keyserver "$KEYSERVER"

printf 'TOKEN=compose-smoke\n' | ENDE_CONFIG_DIR=/tmp/ende-compose/alice "$ENDE" send -t bob --sign-as alice -o /tmp/ende-compose/secret.txt
ENDE_CONFIG_DIR=/tmp/ende-compose/bob "$ENDE" receive -i /tmp/ende-compose/secret.txt -o /tmp/ende-compose/plaintext.txt

grep 'TOKEN=compose-smoke' /tmp/ende-compose/plaintext.txt
echo "compose smoke test passed"
