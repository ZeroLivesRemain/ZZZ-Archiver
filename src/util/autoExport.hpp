#pragma once

#include "../data/exportSettings.hpp"
#include "../pcap/pcap.hpp"
#include "../serialization/zod/IZOD.hpp"
#include "debug.hpp"
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

#ifdef _WIN32
#include <shellapi.h>
#else
#include <cstdlib>
#endif

// Writes the ZOD export to disk automatically, like Reliquary Archiver's archive_output.json.
// Files go to <exe folder>/exports/: one timestamped file per capture session, plus latest.json.
namespace autoexport {
	struct Session {
		std::filesystem::path file{};
	};

	inline std::filesystem::path exportDir() {
		return debug::detail::executablePath().parent_path() / "exports";
	}

	inline std::string timestamp(const char *format) {
		auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
		std::tm local{};
#ifdef _WIN32
		localtime_s(&local, &now);
#else
		localtime_r(&now, &local);
#endif
		char buffer[64]{};
		std::strftime(buffer, sizeof(buffer), format, &local);
		return buffer;
	}

	inline bool writeText(const std::filesystem::path &file, const std::string &text) {
		std::ofstream out(file, std::ios::binary | std::ios::trunc);
		if (!out.is_open()) return false;
		out << text;
		return static_cast<bool>(out);
	}

	// Returns the session file path on success. Safe to call repeatedly: later calls overwrite the same files.
	inline std::optional<std::filesystem::path> write(const Pcap &pcap, const data::ExportSettings &settings, Session &session) {
		auto zod = Serialization::Zod::IZOD::fromPcap(pcap, settings);
		auto json = glz::write_json(zod);
		if (!json) {
			debug::log("Auto-export: failed to serialize ZOD ({})", static_cast<int>(json.error()));
			return std::nullopt;
		}

		std::error_code ec;
		std::filesystem::create_directories(exportDir(), ec);
		if (session.file.empty()) {
			session.file = exportDir() / ("zzz_export_" + timestamp("%Y-%m-%d_%H-%M-%S") + ".json");
		}

		if (!writeText(session.file, *json)) {
			debug::log("Auto-export: could not write {}", session.file.string());
			return std::nullopt;
		}
		writeText(exportDir() / "latest.json", *json);
		debug::log("Auto-export: saved {}", session.file.string());
		return session.file;
	}

	inline void openFolder() {
		std::error_code ec;
		std::filesystem::create_directories(exportDir(), ec);
#ifdef _WIN32
		ShellExecuteW(nullptr, L"open", exportDir().wstring().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
		auto command = "xdg-open \"" + exportDir().string() + "\" >/dev/null 2>&1 &";
		[[maybe_unused]] auto result = std::system(command.c_str());
#endif
	}
}// namespace autoexport
