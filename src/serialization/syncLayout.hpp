#pragma once

#include "../util/debug.hpp"
#include "datamine.hpp"
#include "proto.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace serialization {
	// Where the game's inventory sync notification (sent during play whenever discs, W-Engines or agents change)
	// keeps the changed records.
	//
	// Message and field names in nap.json are obfuscated and change every patch, so the layout is found by structure:
	// the disc, W-Engine and agent record types are read from the three login responses (whose field numbers
	// datamine.json provides), then the notification is the largest message with a command ID that has
	//  - a child block holding repeated discs and repeated W-Engines (the item sync), and
	//  - a separate child block holding repeated agents (the agent sync).
	// For game version 3.3 this resolves to command 515: item block field 3 (discs 6, W-Engines 4), agent block field 7 (agents 14).
	struct SyncLayout {
		uint16_t cmd = 0;
		int32_t itemField = 0;            // field of the notification holding the item sync block
		int32_t discField = 0;            // repeated disc records inside the item block
		int32_t weaponField = 0;          // repeated W-Engine records inside the item block
		std::vector<int32_t> itemUidLists;// repeated integer fields of the item block; lists of removed items live here
		int32_t avatarField = 0;          // field of the notification holding the agent sync block (0 = none)
		int32_t avatarListField = 0;      // repeated agent records inside that block

		[[nodiscard]] bool valid() const {
			return cmd != 0 && itemField != 0 && (discField != 0 || weaponField != 0);
		}

		static SyncLayout find() {
			const auto &datamine = Datamine::get();
			const auto &proto = Proto::get();

			auto fieldType = [&](uint32_t cmd, uint32_t number) -> std::string {
				const auto *entry = proto.getEntryById(static_cast<uint16_t>(cmd));
				if (!entry) return {};
				for (const auto &f: entry->fields) {
					if (f.number == static_cast<int32_t>(number)) return f.type;
				}
				return {};
			};
			const std::string discType = fieldType(datamine.cmdGetEquipDataScRsp, datamine.equipData.discs);
			const std::string weaponType = fieldType(datamine.cmdGetWeaponDataScRsp, datamine.weaponData.weapons);
			const std::string avatarType = fieldType(datamine.cmdGetAvatarDataScRsp, datamine.agentData.agents);
			if (discType.empty() || weaponType.empty()) {
				debug::log("sync: could not find the disc / W-Engine record types; in-session updates are off");
				return {};
			}

			auto repeatedOf = [](const ProtoEntry *entry, const std::string &type) -> int32_t {
				if (type.empty()) return 0;
				for (const auto &f: entry->fields) {
					if (f.repeated && f.type == type) return f.number;
				}
				return 0;
			};

			SyncLayout best{};
			size_t bestScore = 0;
			for (const auto &entry: proto.entries) {
				if (!entry.cmd_id) continue;
				const uint16_t id = *entry.cmd_id;
				if (id == datamine.cmdGetEquipDataScRsp || id == datamine.cmdGetWeaponDataScRsp || id == datamine.cmdGetAvatarDataScRsp) continue;

				SyncLayout layout{};
				layout.cmd = id;
				for (const auto &f: entry.fields) {
					if (f.is_native_type || f.is_enum || f.repeated) continue;
					const auto *child = proto.getEntryByName(f.type);
					if (!child) continue;
					const int32_t d = repeatedOf(child, discType);
					const int32_t w = repeatedOf(child, weaponType);
					const int32_t a = repeatedOf(child, avatarType);
					if (d && w && !layout.itemField) {
						layout.itemField = f.number;
						layout.discField = d;
						layout.weaponField = w;
						for (const auto &g: child->fields) {
							if (g.repeated && g.is_native_type && (g.type == "uint32" || g.type == "uint64" || g.type == "int32" || g.type == "int64")) {
								layout.itemUidLists.push_back(g.number);
							}
						}
						if (a) {
							layout.avatarField = f.number;
							layout.avatarListField = a;
						}
					} else if (a && !d && !w && !layout.avatarField) {
						layout.avatarField = f.number;
						layout.avatarListField = a;
					}
				}
				if (!layout.itemField) continue;

				// The real sync notification carries many kinds of state, so it is by far the largest candidate.
				// A separate agent block is a strong signal too.
				size_t score = entry.fields.size() + ((layout.avatarField && layout.avatarField != layout.itemField) ? 1000 : 0);
				if (score > bestScore) {
					best = layout;
					bestScore = score;
				}
			}

			if (best.valid()) {
				debug::log("sync: notification cmd {} (items in field {}: discs {}, W-Engines {}; agents in field {}: list {})", best.cmd, best.itemField, best.discField, best.weaponField, best.avatarField, best.avatarListField);
			} else {
				debug::log("sync: notification not found in nap.json; in-session updates are off");
			}
			return best;
		}

		static const SyncLayout &get() {
			static SyncLayout layout = find();
			return layout;
		}
	};
}// namespace serialization
