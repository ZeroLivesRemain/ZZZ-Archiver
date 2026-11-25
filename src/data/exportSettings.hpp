#pragma once

#include <cstdint>

namespace data {
	// What goes into an export. Rarity is stored as the game's internal number: 3 = B, 4 = A, 5 = S.
	// Defaults: finished discs only (S rank, level 12+); A and S agents and W-Engines at any level.
	struct ExportSettings {
		uint8_t minDiscRarity = 5;
		uint8_t minDiscLevel = 12;
		uint8_t minEngineRarity = 4;
		uint8_t minEngineLevel = 0;
		uint8_t minAgentRarity = 4;
		uint8_t minAgentLevel = 0;
		bool exportDiscs = true;
		bool exportAgents = true;
		bool exportEngines = true;
	};
}// namespace data
