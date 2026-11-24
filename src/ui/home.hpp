#pragma once

#include "../pcap/pcap.hpp"
#include "core/core.hpp"
#include "data/exportSettings.hpp"
#include "util/appSettings.hpp"
#include "util/autoExport.hpp"
#include <memory>
#include <functional>
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
			std::shared_ptr<std::mutex> statusMutex = std::make_shared<std::mutex>();
			std::string savedPath{};
			std::string savedSummary{};
			uint32_t autoSavedLogin = 0;     // loginSerial of the last login that was auto-saved
			uint32_t pendingChanges = 0;     // copy of pcap.pendingChanges for the UI
			bool loginComplete = false;      // copy of pcap.loginComplete() for the UI
			void saveUpdatedExport();

			std::string loadError{};
			void guarded(const std::function<void()> &fn);
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