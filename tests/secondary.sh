#!/usr/bin/env bash

binary="../pgc"

# this is where the MAC addresses stop
CUT_LEN_START=25

oldtime=$(date +%s.%N)

TOPRINT="/"
animate() {
  # if the last time we were called
  # was too recent, return with no
  # next animation

  curtime=$(date +%s.%N)
  diff=$(echo "$curtime - $oldtime" | bc)


  if (( $(echo "$diff < 0.2" | bc -l) )); then
    return
  fi

  case "$TOPRINT" in
    "/")
      TOPRINT="-"
      ;;
    "-")
      TOPRINT="\\"
      ;;
    "\\")
      TOPRINT="|"
      ;;
    "|")
      TOPRINT="/"
      ;;
  esac

  oldtime="$curtime"

}

for _ in {1..400}; do
  # find a random length
  len=$(( RANDOM % 300 + 1 ))
  # make it always be an even number
  len=$(( "$len" * 2 ))
  # then find the length we will use in cut
  len2=$(( "$CUT_LEN_START" + len - 1))

  # create a random hex string
  input=$(tr -dc 'a-f0-9' < /dev/urandom | fold -w "$len" | head -n 1)

  # give it to our program
  "$binary" -r "$input"

  # when we read its output, it should be the same we generated as input
  output=$(tcpdump -xx -r paibuild.pcap 2>&1 | cut -d":" -f2- | tail -n+3 | tr -d " \t\n\r" | cut -c"$CUT_LEN_START"-"$len2")
  if [[ "$input" != "$output" ]]; then
    echo "error"
    echo "$input"
    echo "/="
    echo "$output"
    exit 1
  else
    animate
    printf "\r%s      " $TOPRINT
  fi
done



printf "\r"
echo "PASS"
exit 0


