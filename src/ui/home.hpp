#pragma once

#include "../pcap/pcap.hpp"
#include "core/core.hpp"
#include "data/exportSettings.hpp"
#include "util/appSettings.hpp"
#include "util/autoExport.hpp"
#include <mutex>

namespace ui {
	using namespace squi;

	struct Home : StatefulWidget {
		// Args
		Key key;
		Args widget{};

		struct State : WidgetState<Home> {
			bool isLoading = true;
			bool isCapturing = false;
			bool manifestUpdateAvailable = false;
			data::ExportSettings exportSettings;
			Pcap pcap;
			VoidObserver onEventUpdate{};

			// Auto-export additions
			appsettings::AppSettings settings{};
			autoexport::Session exportSession{};
			bool autoUpdatePending = false;
			std::mutex statusMutex;
			std::string savedPath{};
			std::string savedSummary{};

			void applySavedRegionAndAutoStart();
			void handleCaptureEvent();
			std::string statusText();

			void initState() override;

			void updateData();
			void initializeData();

			void dispose() override {
				pcap.stop();
			}

			std::optional<std::string> getSelectedRegion();

			Child build(const Element &element) override;
		};
	};
}// namespace ui