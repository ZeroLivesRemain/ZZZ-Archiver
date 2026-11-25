#include "exportSettings.hpp"
#include "widgets/button.hpp"
#include "widgets/column.hpp"
#include "widgets/dropdownButton.hpp"
#include "widgets/expander.hpp"
#include "widgets/iconButton.hpp"
#include "widgets/row.hpp"
#include "widgets/slider.hpp"
#include "widgets/text.hpp"
#include "widgets/toggleSwitch.hpp"

namespace ui {
	namespace {
		// The game ranks items B, A and S; exports store them as 3, 4 and 5.
		std::string rankName(uint8_t rarity) {
			switch (rarity) {
				case 3: return "B";
				case 4: return "A";
				case 5: return "S";
				default: return std::format("{}", rarity);
			}
		}
	}// namespace

	squi::core::Child ExportSettings::State::build(const Element &element) {
		auto &s = widget->exportSettings;
		auto changed = [this]() {
			setState();
			if (widget->onChange) widget->onChange();
		};

		// One row: on/off switch, minimum level slider (with its value) and minimum rank menu.
		auto row = [&](std::string title, bool &enabled, uint8_t &minLevel, float maxLevel, float tick, uint8_t &minRarity, uint8_t lowestRarity) -> Child {
			return ExpanderItem{
				.icon = ToggleSwitch{
					.active = enabled,
					.statePosition = ToggleSwitch::StatePosition::None,
					.onToggle = [&enabled, changed](bool val) {
						enabled = val;
						changed();
					},
				},
				.title = title,
				.action = Row{
					.widget{
						.width = Size::Wrap,
						.height = Size::Wrap,
					},
					.crossAxisAlignment = Flex::Alignment::center,
					.spacing = 8.f,
					.children{
						Text{
							.widget{.sizeConstraints{.minWidth = 92.f}},
							.text = std::format("Min level {}", minLevel),
						},
						Slider{
							.widget{
								.sizeConstraints{
									.maxWidth = 200.f,
								},
							},
							.minValue = 0.f,
							.maxValue = maxLevel,
							.value = static_cast<float>(minLevel),
							.disabled = !enabled,
							.ticks = Slider::TickInterval{tick},
							.onChange = [&minLevel, changed](float newVal) {
								minLevel = static_cast<uint8_t>(newVal);
								changed();
							},
						},
						DropdownButton{
							.disabled = !enabled,
							.text = std::format("Min rank {}", rankName(minRarity)),
							.items = [&]() {
								std::vector<ContextMenu::Item> items;
								for (uint8_t i = lowestRarity; i <= 5; ++i) {
									items.push_back(ContextMenu::Button{
										.text = rankName(i),
										.callback = [&minRarity, changed, i]() {
											minRarity = i;
											changed();
										},
									});
								}
								return items;
							}(),
						},
					},
				},
			};
		};

		auto part = [](bool on, std::string name, uint8_t rarity, uint8_t level) {
			if (!on) return std::format("{}: off", name);
			return level > 0 ? std::format("{}: {} rank+, level {}+", name, rankName(rarity), level) : std::format("{}: {} rank+", name, rankName(rarity));
		};
		const bool open = widget->expanded;

		// The library's Expander has no open/close callback, so this section draws its own arrow and is rebuilt
		// (new key) in the new state; the state is saved by the parent.
		return Expander{
			.key = IndexKey(open ? 1 : 0),
			.title = "Export settings",
			.subtitle = open ? std::string{} : part(s.exportDiscs, "Discs", s.minDiscRarity, s.minDiscLevel) + " · " + part(s.exportAgents, "Agents", s.minAgentRarity, s.minAgentLevel) + " · " + part(s.exportEngines, "W-Engines", s.minEngineRarity, s.minEngineLevel),
			.alwaysExpanded = open,
			.action = IconButton{
				.widget{
					.margin = Margin{}.withLeft(16.f),
				},
				.icon = open ? static_cast<char32_t>(0xe316) : static_cast<char32_t>(0xe313),
				.theme = Button::Theme::Subtle(),
				.onClick = [this, open]() {
					if (widget->onExpandedChange) widget->onExpandedChange(!open);
				},
			},
			.content = open ? Child{Column{
								  .spacer = ExpanderItemSpacer{},
								  .children{
									  row("Discs", s.exportDiscs, s.minDiscLevel, 15.f, 3.f, s.minDiscRarity, 3),
									  row("Agents", s.exportAgents, s.minAgentLevel, 60.f, 10.f, s.minAgentRarity, 4),
									  row("W-Engines", s.exportEngines, s.minEngineLevel, 60.f, 10.f, s.minEngineRarity, 3),
								  },
							  }}
							: Child{},
		};
	}
}// namespace ui
