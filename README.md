# ZZZ Packet Capture — auto-export edition

A fork of [AleXu224/zzz_packet_capture](https://github.com/AleXu224/zzz_packet_capture) (MIT) that works more like Reliquary Archiver:

- **Saves the export automatically.** As soon as your agents, W-Engines and discs are captured, a ZOD JSON file is written to the `exports` folder next to the program: `zzz_export_<date>_<time>.json`, plus `latest.json`, which is always the newest. No "Copy to clipboard" step needed (the button still works).
- **Remembers your region** and **starts capturing on launch**, so the routine is: open the program, open the game, log in, done.
- **Updates game data automatically** after a patch instead of asking (it still downloads the data files published by the original project).
- The **Automatic export** panel shows where the file was saved and has an **Open exports folder** button. All three behaviours can be switched off there.

Settings are stored in `settings.json` next to the program. All credit for the capture and decoding work goes to AleXu224 and contributors; this fork only changes how results are saved.

## Quick start (Windows)
1. Download `zzz_packet_capture_auto_export.zip` from this repository's **Releases** page and extract it.
2. Run `zzz_packet_capture.exe` (it asks for administrator rights — packet capture needs them).
3. First time only: pick your region and press **Start capture**.
4. Launch Zenless Zone Zero and log in. When your character appears, the file is in `exports\latest.json`.
5. Import that file into your optimizer.

---

# About
A packet capture based scanner for Zenless Zone Zero. Used to quickly gather all your discs, engines and agents data from the game in a single click.

It can be used to quickly import all your data into [Zenless Optimizer](https://frzyc.github.io/zenless-optimizer/) or other tools that accept the same data format.

![](preview.png)
# Usage
- Download the latest version from the [releases page](https://github.com/AleXu224/zzz_packet_capture/releases)
- Extract the archive to a folder of your choice and start `zzz_packet_capture.exe`
  - The program needs to start with administrator privileges in order to capture packets from the game, you will automatically be prompted to do so
  - On linux you will need to manually start the program with sudo or run `sudo setcap cap_net_raw,cap_net_admin=eip zzz_packet_capture` to allow it to capture packets without root privileges
- Choose your region and click "Start Capture"
- Close Zenless Zone Zero if you haven't done so already
- Start the game and log in, the program will automatically capture your data (should be done by the time you see your character in game)
- Adjust your export settings if you want to, then click "Copy to clipboard" to get the exported data

# Disclaimer
This is gonna break every time a new version comes out. I am singlehandedly maintaining this and reverse engineering is not exactly my forte, so it might take a bit for me to get it working again. If you have experience and want to help your best bet is to help with updating [GracefulDumper](https://github.com/AleXu224/GracefulDumper) to the latest version of the game, since that is the main blocker.

If you are eager to help but have no experience then please don't hesitate to reach out and ask for how things are done, I might not be the best at it myself but I can certainly help you get started.

# Building

- Requirements:
  - [CMake](https://github.com/kitware/cmake)
  - A recent release of [Clang](https://github.com/llvm/llvm-project)
    - Other compilers might work but I rarely test them
  - [Ninja](https://github.com/ninja-build/ninja)
    - Optional, but recommended for faster builds
  - [Vulkan SDK](https://vulkan.lunarg.com/sdk/home)
  - Windows: Visual Studio or Visual Studio Build Tools
    - Make sure to install the "Desktop development with C++" workload
  - Linux: only tested with libstdc++ 
    - other dependencies depend on too many factors to list, CMake will tell you what is missing and needs installing
- Building:
  - Clone the repository and initialize the submodules:
  ```bash
  git clone https://github.com/AleXu224/zzz_packet_capture
  cd zzz_packet_capture
  git submodule update --init --recursive
  ```
  - Run cmake to generate the build files and install the dependencies (this will take a while):
  ```bash
  cmake -B build -G "Ninja Multi-Config" -DCMAKE_C_COMPILER="clang" -DCMAKE_CXX_COMPILER="clang++"
  
  cd build

  ninja
  # or if you want to build a release version
  ninja -f ./build-Release.ninja
  ```

# Credits
Massive thanks to the Reversed Rooms Discord for helping me with the reverse engineering. I wouldn't have been able to do this without them
