touch temp_output.json
tail -f temp_compile_commands.json | while read line; do
    echo "$line" >> temp_output.json
done &
TAIL_PID=$!

BPF_EXTRA_CFLAGS_PRE_INCL="-MJ temp_compile_commands.json" cargo build 

kill $TAIL_PID

echo '[' > compile_commands.json
cat temp_output.json >> compile_commands.json
sed -i '$ s/,$//' compile_commands.json
echo ']' >> compile_commands.json
