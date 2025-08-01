while true; do
    ./samples/a.out
    if [ $? -ne 0 ]; then
        echo "Program exited with non-zero status, stopping loop"
        break
    fi
done
