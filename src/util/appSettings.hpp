#pragma once

#include "debug.hpp"
#include "serializable.hpp"
#include <filesystem>
#include <string>

// Persistent user preferences, stored as settings.json next to the executable.
namespace appsettings {
	struct AppSettings {
		std::string region{};       // last region picked in the dropdown
		bool autoStart = true;      // start capturing on launch when a region is remembered
		bool autoSave = true;       // write the ZOD export to disk as soon as data is captured
		bool autoUpdateData = true; // download new data files without asking
	};

	inline std::filesystem::path path() {
		return debug::detail::executablePath().parent_path() / "settings.json";
	}

	inline AppSettings load() {
		return util::serializable::fromFile<AppSettings>(path().string()).value_or(AppSettings{});
	}

	inline void save(const AppSettings &settings) {
		util::serializable::toFile(settings, path().string());
	}
}// namespace appsettings
