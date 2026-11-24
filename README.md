# ZZZ Disc Archiver

Captures your Zenless Zone Zero agents, W-Engines and Drive Discs while you play and saves them as a JSON file for disc optimizers (ZOD format, the same format Zenless Optimizer and similar tools import). It works like Reliquary Archiver does for Honkai: Star Rail: open it, log in, and the file is written for you.

## Quick guide (Windows)

1. **Download** `ZZZ-Disc-Archiver.zip` from the [Releases](../../releases) page and extract it to a folder of your choice.
2. **Run** `ZZZ-Disc-Archiver.exe`. Windows asks for administrator rights, which packet capture needs. Capture starts right away; there's no region to pick.
3. **Log in** to Zenless Zone Zero. If the game is already open, log out to the title screen and back in, because your inventory is only sent at login.
4. **Get the file.** When your character appears, the export is saved to `exports\latest.json` in the program's folder, plus a dated copy (`zzz_export_<date>_<time>.json`). Import `latest.json` into your optimizer.
5. **Keep it open while you play** (optional). New discs, upgrades, equip changes, W-Engines and agents are tracked as they happen. When you want them in your optimizer, press **Save updated export**: the button shows how many changes are waiting, and a fresh `latest.json` is written. Earlier files are kept.

## The window

- **Status card:** what the program is doing (waiting for login, export saved, or how many changes are waiting), the last saved file, and the **Save updated export** and **Open exports folder** buttons. Capture runs the whole time the program is open.
- **Settings:** your region (detected automatically at login) and three switches: save automatically at login, start capturing when the program opens, and update game data automatically.
- **Export settings:** which discs, agents and W-Engines to include (minimum level and rarity).
- **Copy to clipboard instead:** for tools that take a pasted export.
- **Agents / Engines / Discs** (left-hand pages): what has been captured so far.

Settings are saved in `settings.json` next to the program. If something goes wrong, `logs\zzz_disc_archiver.log` in the same folder says what happened.

## After a game update

The game's packet layout changes with most patches. The program downloads the updated decoding data published by the original project when it's available. If capture stops working after a patch, check the Releases page for a newer build.

## Credits

This is a fork of [zzz_packet_capture](https://github.com/AleXu224/zzz_packet_capture) by **AleXu224**, who wrote the packet capture, decryption and decoding this tool is built on, and who keeps the game data up to date after each patch. AleXu224 in turn thanks the Reversed Rooms Discord for their help with the reverse engineering. This fork adds automatic saving, start-on-launch with region detection, and in-session updates. It is released under the same MIT license; see [LICENSE](LICENSE).
