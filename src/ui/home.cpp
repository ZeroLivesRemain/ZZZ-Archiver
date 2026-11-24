#include "home.hpp"
#include "core/clipboard.hpp"
#include "serialization/datamine.hpp"
#include "serialization/manifest.hpp"
#include "serialization/zod/IZOD.hpp"
#include "theme.hpp"
#include "ui/exportSettings.hpp"
#include "util/debug.hpp"
#include "widgets/box.hpp"
#include "widgets/button.hpp"
#include "widgets/card.hpp"
#include "widgets/column.hpp"
#include "widgets/dropdownButton.hpp"
#include "widgets/expander.hpp"
#include "widgets/fontIcon.hpp"
#include "widgets/row.hpp"
#include "widgets/scrollview.hpp"
#include "widgets/text.hpp"
#include "widgets/toggleSwitch.hpp"
#include "widgets/topNav.hpp"
#include <filesystem>


namespace ui {
	void Home::State::initState() {
		settings = appsettings::load();
		auto task = std::thread([this]() { guarded([&]() {
			std::filesystem::path assetsPath = "assets";
			if (!std::filesystem::exists(assetsPath)) {
				std::filesystem::create_directory(assetsPath);
			}

			auto localManifest = serialization::Manifest::get();
			auto latestManifest = util::serializable::fromNetwork<serialization::Manifest>(serialization::manifestUrl);
			auto localVersion = util::Version::parse(localManifest.version);
			auto latestVersion = latestManifest ? util::Version::parse(latestManifest->version) : localVersion;
			if (localVersion < latestVersion) {
				if (settings.autoUpdateData) {
					autoUpdatePending = true;
				} else {
					manifestUpdateAvailable = true;
				}
			} else {
				serialization::NanokaData::get();
				serialization::Datamine::get();
				serialization::Proto::get();
			}

			// crypto::xorpad::initialSeed = std::stoull(serialization::Datamine::get().xorSeeds.at("Europe"), nullptr, 16);
			// pcap.loadCapturePacketsFromFile();
			onEventUpdate = pcap.onEventUpdate.observe([this]() {
				handleCaptureEvent();
				setState();
			});
			setState([&]() {
				isLoading = false;
			});
			if (autoUpdatePending) {
				autoUpdatePending = false;
				updateData();
			} else if (!manifestUpdateAvailable) {
				applySavedRegionAndAutoStart();
			}
		}); });
		task.detach();
	}

	// Background loading must never take the whole program down: report the problem on screen instead.
	void Home::State::guarded(const std::function<void()> &fn) {
		try {
			fn();
		} catch (const std::exception &e) {
			debug::log("Startup error: {}", e.what());
			std::string message = e.what();
			setState([&]() {
				loadError = message;
				isLoading = false;
			});
		} catch (...) {
			debug::log("Startup error: unknown exception");
			setState([&]() {
				loadError = "Unknown error";
				isLoading = false;
			});
		}
	}

	// Capture starts as soon as the program is ready. The region no longer has to be picked: the login packet is
	// decrypted with each region's key until one works (see Pcap::detectRegionAndServerKey). A remembered region is
	// only tried first.
	void Home::State::applySavedRegionAndAutoStart() {
		auto &datamine = serialization::Datamine::get();
		if (!settings.region.empty() && !crypto::xorpad::initialSeed) {
			if (auto it = datamine.xorSeeds.find(settings.region); it != datamine.xorSeeds.end()) {
				crypto::xorpad::initialSeed = std::stoull(it->second, nullptr, 16);
			}
		}
		if (settings.autoStart && !isCapturing) {
			pcap.listen();
			setState([&]() {
				isCapturing = true;
			});
		} else {
			setState();
		}
	}

	// Called on the capture thread after each decoded event.
	void Home::State::handleCaptureEvent() {
		uint32_t login = 0;
		bool complete = false;
		uint32_t pending = 0;
		std::optional<std::string> detected;
		{
			std::scoped_lock lock{*pcap.dataMutex};
			login = pcap.loginSerial;
			complete = pcap.loginComplete();
			pending = pcap.pendingChanges;
			detected = pcap.detectedRegion;
		}
		if (detected && *detected != settings.region) {
			settings.region = *detected;
			appsettings::save(settings);
		}
		{
			std::scoped_lock lock{*statusMutex};
			loginComplete = complete;
			pendingChanges = pending;
		}

		// The full export is written once per login, as soon as all three lists have arrived.
		// Changes made while playing are saved with the "Save updated export" button.
		if (!complete || !settings.autoSave || autoSavedLogin == login) return;
		autoSavedLogin = login;
		exportSession = {};
		auto path = autoexport::write(pcap, exportSettings, exportSession);
		if (!path) return;
		std::scoped_lock lock{*pcap.dataMutex, *statusMutex};
		pcap.pendingChanges = 0;
		pendingChanges = 0;
		savedPath = path->string();
		savedSummary = std::format("{} discs · {} agents · {} W-Engines", pcap.discs.size(), pcap.agents.size(), pcap.engines.size());
		savedTime = autoexport::timestamp("%H:%M:%S");
	}

	// Writes a new timestamped file (and latest.json) with everything captured so far, including changes made
	// while playing. Earlier files are kept, so each save can be imported or compared on its own.
	void Home::State::saveUpdatedExport() {
		exportSession = {};
		auto path = autoexport::write(pcap, exportSettings, exportSession);
		if (!path) return;
		{
			std::scoped_lock lock{*pcap.dataMutex, *statusMutex};
			pcap.pendingChanges = 0;
			pendingChanges = 0;
			savedPath = path->string();
			savedSummary = std::format("{} discs · {} agents · {} W-Engines", pcap.discs.size(), pcap.agents.size(), pcap.engines.size());
		savedTime = autoexport::timestamp("%H:%M:%S");
		}
		setState();
	}

	// The status card: one short headline, then the details on a wrapped line of their own.
	std::string Home::State::statusHeadline() {
		std::scoped_lock lock{*statusMutex};
		if (!isCapturing) return "Capture is off";
		if (!loginComplete) return "Waiting for login";
		if (pendingChanges > 0) return std::format("{} change{} since the last save", pendingChanges, pendingChanges == 1 ? "" : "s");
		if (!savedPath.empty()) return "Export saved";
		return "Data captured";
	}

	std::string Home::State::statusDetail() {
		std::scoped_lock lock{*statusMutex};
		const std::string file = savedPath.empty() ? std::string{} : std::filesystem::path(savedPath).filename().string();
		if (!isCapturing) return "Press Start capture, then log in to Zenless Zone Zero.";
		if (!loginComplete) return "Launch Zenless Zone Zero and log in. If it's already open, log out to the title screen and back in.";
		if (pendingChanges > 0) return file.empty() ? "Press Save updated export to write the file." : std::format("Press Save updated export to write a new file. Last saved at {}: {}", savedTime, file);
		if (!savedPath.empty()) return std::format("{} · saved at {} as {}. Changes you make in game are tracked while capture runs.", savedSummary, savedTime, file);
		return "Press Save updated export to write the file.";
	}

	void Home::State::updateData() {
		setState([&]() {
			isLoading = true;
		});
		auto task = std::thread([this]() { guarded([&]() {
			auto latestManifest = util::serializable::fromNetwork<serialization::Manifest>(serialization::manifestUrl);
			if (!latestManifest) {
				debug::log("Failed to fetch latest manifest.json");
				setState([&]() {
					isLoading = false;
				});
				applySavedRegionAndAutoStart();
				return;
			}

			auto latestDatamine = util::serializable::fromNetwork<serialization::Datamine>(serialization::datamineUrl);
			if (!latestDatamine) {
				debug::log("Failed to fetch latest datamine.json");
				setState([&]() {
					isLoading = false;
				});
				applySavedRegionAndAutoStart();
				return;
			}

			auto latestProto = util::serializable::fromNetwork<std::vector<serialization::ProtoEntry>>(serialization::protoUrl);
			if (!latestProto) {
				debug::log("Failed to fetch latest nap.json");
				setState([&]() {
					isLoading = false;
				});
				applySavedRegionAndAutoStart();
				return;
			}

			util::serializable::toFile(*latestManifest, serialization::manifestPath);
			util::serializable::toFile(*latestDatamine, serialization::dataminePath);
			util::serializable::toFile(*latestProto, serialization::protoPath);

			serialization::NanokaData::get();
			serialization::Datamine::get();
			serialization::Proto::get();

			setState([&]() {
				isLoading = false;
				manifestUpdateAvailable = false;
			});
			applySavedRegionAndAutoStart();
		}); });
		task.detach();
	}

	void Home::State::initializeData() {
		setState([&]() {
			isLoading = true;
		});
		auto task = std::thread([this]() { guarded([&]() {
			serialization::NanokaData::get();
			serialization::Datamine::get();
			serialization::Proto::get();
			setState([&]() {
				isLoading = false;
			});
			applySavedRegionAndAutoStart();
		}); });
		task.detach();
	}

	std::optional<std::string> Home::State::getSelectedRegion() {
		if (!crypto::xorpad::initialSeed) {
			return std::nullopt;
		}

		auto &datamine = serialization::Datamine::get();
		std::string seedHex = std::format("{:016X}", *crypto::xorpad::initialSeed);
		for (const auto &[region, seed]: datamine.xorSeeds) {
			if (seed == seedHex) {
				return region;
			}
		}

		return std::nullopt;
	}


	Child Home::State::statusCard(const Element &element) {
		const bool waiting = isCapturing && !loginComplete;
		const bool attention = loginComplete && pendingChanges > 0;
		return Card{
			.widget{
				.height = Size::Wrap,
				.padding = Padding{16.f},
			},
			.child = Column{
				.widget{.height = Size::Wrap},
				.spacing = 10.f,
				.children{
					Row{
						.widget{.height = Size::Wrap},
						.crossAxisAlignment = Flex::Alignment::center,
						.spacing = 10.f,
						.children{
							FontIcon{
								.size = 22.f,
								.fontSize = 22.f,
								.font = FontStore::defaultIconsFilled,
								.color = !isCapturing ? Color(0xFFFFFF80) : (waiting || attention) ? Color(0xFFC857FF) : Theme::of(element).accent,
								.icon = static_cast<char32_t>(!isCapturing || waiting ? 0xe8b5 : attention ? 0xe627 : 0xe86c),// schedule / sync / check_circle
							},
							Text{
								.text = statusHeadline(),
								.fontSize = 18.f,
							},
						},
					},
					Text{
						.text = statusDetail(),
						.lineWrap = true,
						.color = Color(0xFFFFFFB4),
					},
					Row{
						.widget{.height = Size::Wrap},
						.spacing = 8.f,
						.children{
							Button{
								.disabled = !loginComplete,
								.onClick = [this]() {
									saveUpdatedExport();
								},
								.child = pendingChanges > 0 ? std::format("Save updated export ({})", pendingChanges) : std::string{"Save updated export"},
							},
							Button{
								.onClick = []() {
									autoexport::openFolder();
								},
								.child = "Open exports folder",
							},
							Button{
								.onClick = [this]() {
									if (isCapturing) {
										pcap.stop();
									} else {
										pcap.listen();
									}
									setState([&]() {
										isCapturing = !isCapturing;
									});
								},
								.child = isCapturing ? "Stop capture" : "Start capture",
							},
						},
					},
				},
			},
		};
	}

	Child Home::State::settingsSection() {
		auto toggle = [this](bool value, std::function<void(bool)> set) {
			return ToggleSwitch{
				.active = value,
				.statePosition = ToggleSwitch::StatePosition::None,
				.onToggle = [this, set](bool val) {
					setState([&]() {
						set(val);
					});
					appsettings::save(settings);
				},
			};
		};
		auto region = getSelectedRegion();
		return Expander{
			.title = "Settings",
			.subtitle = region ? std::format("Region: {}", *region) : std::string{"Region: detected when you log in"},
			.content = Column{
				.spacer = ExpanderItemSpacer{},
				.children{
					ExpanderItem{
						.title = "Region",
						.subtitle = "Detected automatically from your login and remembered. Change it only if detection fails.",
						.action = DropdownButton{
							.text = region.value_or("Auto-detect"),
							.items = [&]() {
								std::vector<ContextMenu::Item> items;
								auto &datamine = serialization::Datamine::get();
								for (const auto &[name, seed]: datamine.xorSeeds) {
									items.push_back(ContextMenu::Button{
										.text = name,
										.callback = [this, seed, name]() {
											crypto::xorpad::initialSeed = std::stoull(seed, nullptr, 16);
											settings.region = name;
											appsettings::save(settings);
											setState();
										},
									});
								}
								return items;
							}(),
						},
					},
					ExpanderItem{
						.icon = toggle(settings.autoSave, [this](bool v) { settings.autoSave = v; }),
						.title = "Save automatically when you log in",
						.subtitle = "Writes a dated file and latest.json to the exports folder as soon as your data is captured.",
					},
					ExpanderItem{
						.icon = toggle(settings.autoStart, [this](bool v) { settings.autoStart = v; }),
						.title = "Start capturing when the program opens",
					},
					ExpanderItem{
						.icon = toggle(settings.autoUpdateData, [this](bool v) { settings.autoUpdateData = v; }),
						.title = "Update game data automatically",
						.subtitle = "Downloads new decoding data after a game patch without asking.",
					},
				},
			},
		};
	}

	squi::core::Child Home::State::build(const Element &element) {
		if (isLoading) {
			return Text{
				.widget{
					.alignment = squi::core::Alignment::Center,
				},
				.text = "Loading...",
			};
		}

		if (!loadError.empty()) {
			return Column{
				.widget{
					.width = Size::Shrink,
					.height = Size::Shrink,
					.alignment = squi::core::Alignment::Center,
				},
				.crossAxisAlignment = Flex::Alignment::center,
				.spacing = 8.f,
				.children{
					Text{.text = "Could not load the game data: " + loadError},
					Text{.text = "Check your internet connection and start the program again."},
					Text{.text = "Details are in logs\\zzz_packet_capture.log next to the program."},
				},
			};
		}

		if (manifestUpdateAvailable) {
			return Column{
				.widget{
					.width = Size::Shrink,
					.height = Size::Shrink,
					.alignment = squi::core::Alignment::Center,
				},
				.crossAxisAlignment = Flex::Alignment::center,
				.spacing = 8.f,
				.children{
					Text{
						.widget{
							.alignment = squi::core::Alignment::Center,
						},
						.text = "New data files are available. Would you like to update?",
					},
					Row{
						.widget{
							.width = Size::Shrink,
						},
						.spacing = 8.f,
						.children{
							Button{
								.onClick = [this]() {
									updateData();
								},
								.child = "Yes",
							},
							Button{
								.onClick = [this]() {
									setState([&]() {
										manifestUpdateAvailable = false;
									});
									initializeData();
								},
								.child = "No",
							},
						},
					},
				}
			};
		}

		return TopNav{
			.pages{
				TopNav::Page{
					.name = "Scan",
					.content = ScrollView{
						.key = IndexKey(0),
						.scrollWidget{
							.padding = 8.f,
						},
						.spacing = 4.f,
						.children{
							statusCard(element),
							settingsSection(),
							ui::ExportSettings{
								.exportSettings = exportSettings,
							},
							Expander{
								.title = "Copy to clipboard instead",
								.subtitle = "For tools that take a pasted export. Uses the export settings above.",
								.action = Button{
									.onClick = [this]() {
										auto json = [&]() {
											std::scoped_lock lock{*pcap.dataMutex};
											auto zod = Serialization::Zod::IZOD::fromPcap(pcap, exportSettings);
											return glz::write_json(zod);
										}();
										if (!json) {
											debug::log("Failed to serialize ZOD: {}", static_cast<int>(json.error()));
											return;
										}
										Clipboard::of(this).set(*json);
									},
									.child = "Copy",
								},
							},
						},
					},
				},
				TopNav::Page{
					.name = pcap.agents.empty() ? std::string{"Agents"} : std::format("Agents {}", pcap.agents.size()),
					.icon = pcap.agents.empty()//
							  ? Child{}
							  : FontIcon{
									.font = FontStore::defaultIconsFilled,
									.color = Theme::of(element).accent,
									.icon = 0xe86c,
								},
					.content = ScrollView{
						.key = IndexKey(1),
						.scrollWidget{.padding = 8.f},
						.spacing = 8.f,
						.children = [&]() {
							Children ret;
							std::scoped_lock lock{*pcap.dataMutex};

							for (const auto &[index, agent]: pcap.agents | std::views::enumerate) {
								ret.emplace_back(
									Expander{
										.title = std::format("Agent {}", index),
										.subtitle = std::format("ID: {} Name: {} Level: {} Promotion: {} Weapon UID: {} Mindscape: {}", agent.id, agent.name(), agent.level, agent.promotion, agent.weaponUid, agent.mindscape),
									}
								);
							}

							return ret;
						}(),
					},
				},
				TopNav::Page{
					.name = pcap.engines.empty() ? std::string{"Engines"} : std::format("Engines {}", pcap.engines.size()),
					.icon = pcap.engines.empty()//
							  ? Child{}
							  : FontIcon{
									.font = FontStore::defaultIconsFilled,
									.color = Theme::of(element).accent,
									.icon = 0xe86c,
								},
					.content = ScrollView{
						.key = IndexKey(2),
						.scrollWidget{.padding = 8.f},
						.spacing = 8.f,
						.children = [&]() {
							Children ret;
							std::scoped_lock lock{*pcap.dataMutex};

							for (const auto &[index, engine]: pcap.engines | std::views::enumerate) {
								ret.emplace_back(
									Expander{
										.title = std::format("Engine {}", index),
										.subtitle = std::format("ID: {} Name: {} UID: {} Level: {} Phase: {} Modification: {}", engine.id, engine.name(), engine.uid, engine.level, engine.phase, engine.modification),
									}
								);
							}

							return ret;
						}(),
					},
				},
				TopNav::Page{
					.name = pcap.discs.empty() ? std::string{"Discs"} : std::format("Discs {}", pcap.discs.size()),
					.icon = pcap.discs.empty()//
							  ? Child{}
							  : FontIcon{
									.font = FontStore::defaultIconsFilled,
									.color = Theme::of(element).accent,
									.icon = 0xe86c,
								},
					.content = ScrollView{
						.key = IndexKey(3),
						.scrollWidget{.padding = 8.f},
						.spacing = 8.f,
						.children = [&]() {
							Children ret;
							std::scoped_lock lock{*pcap.dataMutex};

							for (const auto &[index, disc]: pcap.discs | std::views::enumerate) {
								ret.emplace_back(
									Expander{
										.title = std::format("Disc {}", index),
										.subtitle = std::format("ID: {} Level: {}, Rarity: {}, Slot: {}, Set: {}", disc.id, disc.level, disc.getRarity(), disc.getSlot(), disc.getSetName()),
									}
								);
							}

							return ret;
						}(),
					},
				},
			},
		};
	}
}// namespace ui