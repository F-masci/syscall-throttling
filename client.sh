ITERATIONS=5
if [ $# -gt 0 ]; then
    ITERATIONS=$1
fi

if [ "$ITERATIONS" -lt 0 ]; then
    echo "Invalid number of iterations."
    exit 1
fi

if [ ! -f ./client/client ]; then
    echo "Client binary not found! Please compile the client first."
    exit 1
fi

echo "Running client $ITERATIONS times..."
for ((i=1; i<=ITERATIONS; i++)); do
    echo "Iteration $i:"
    ./client/client /dev/sct/monitor0
done

