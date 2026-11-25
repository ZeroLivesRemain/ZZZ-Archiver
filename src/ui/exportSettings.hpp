#pragma once

#include "core/core.hpp"
#include "data/exportSettings.hpp"
#include <functional>

namespace ui {
	using namespace squi;

	struct ExportSettings : StatefulWidget {
		// Args
		Key key;
		Args widget{};
		data::ExportSettings &exportSettings;
		bool expanded = true;                    // section open; remembered in settings.json
		std::function<void(bool)> onExpandedChange{};
		std::function<void()> onChange{};       // a filter changed (saved to settings.json)

		struct State : WidgetState<ExportSettings> {
			Child build(const Element &element) override;
		};
	};
}// namespace ui