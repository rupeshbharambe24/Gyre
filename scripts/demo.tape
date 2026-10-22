# VHS tape — turns scripts/demo.sh into an animated GIF for the README.
#
# One-time: install VHS (https://github.com/charmbracelet/vhs) — free/open-source — and ffmpeg.
# Then, from the repo root:
#
#   cargo build --release -p gyre-cli   # build once so the GIF opens on the demo, not a compile log
#   vhs scripts/demo.tape               # writes docs/assets/demo.gif
#
# Prefer asciinema? No VHS needed:
#   asciinema rec demo.cast -c "PAUSE=0.8 ./scripts/demo.sh"   # records a terminal cast
#   agg demo.cast docs/assets/demo.gif                          # cast -> GIF (github.com/asciinema/agg)

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 780
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 25ms

# A snappier pace reads better as a looping GIF than the default.
Env PAUSE "0.8"
Env FLOOD "50"

Type "./scripts/demo.sh"
Sleep 400ms
Enter

# Let the four steps play out (relay start + origin park + solve + flood).
Sleep 14s
