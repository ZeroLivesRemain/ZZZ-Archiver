#pragma once

#include "debug.hpp"
#include "serializable.hpp"
#include "data/exportSettings.hpp"
#include <filesystem>
#include <string>

// Persistent user preferences, stored as settings.json next to the executable.
namespace appsettings {
	struct AppSettings {
		std::string region{};       // region detected at the last login (tried first next time)
		bool autoStart = true;      // start capturing as soon as the program opens
		bool autoSave = true;       // write the ZOD export to disk as soon as data is captured
		bool autoUpdateData = true; // download new data files without asking
		data::ExportSettings exportFilters{}; // last export settings used
		bool exportExpanded = true; // Export settings section open (open on first run)
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
