#pragma once

#include "../crypto/session.hpp"
#include "../crypto/xorProtoFields.hpp"
#include "../data/agent.hpp"
#include "../data/disc.hpp"
#include "../data/engine.hpp"
#include "../kcp/kcp.hpp"
#include "../kcp/messageHeader.hpp"
#include "../serialization/datamine.hpp"
#include "../serialization/packets.hpp"
#include "../serialization/proto.hpp"
#include "../serialization/syncLayout.hpp"
#include "../util/debug.hpp"
#include "glaze/glaze.hpp"// IWYU pragma: keep
#include "google/protobuf/unknown_field_set.h"
#include "observer.hpp"
#include <algorithm>
#include <format>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>
#ifdef _WIN32
#include "pktmonDevice.hpp"
#else
#include <pcapplusplus/PcapFilter.h>
#include <pcapplusplus/PcapLiveDevice.h>
#include <pcapplusplus/PcapLiveDeviceList.h>
#endif
#include <ranges>
#include <thread>


// #include "util/proto.hpp"

struct Pcap {
	serialization::PacketList capturedPackets;
	std::vector<std::shared_ptr<google::protobuf::UnknownFieldSet>> parsedPackets;
	std::vector<data::DiscInfo> discs;
	std::vector<data::WeaponInfo> engines;
	std::vector<data::AgentInfo> agents;
	crypto::Session session{};
	KCP::KCP kcp{};
	squi::VoidObservable onEventUpdate{};

	// Guards discs / engines / agents and the counters below: packets are decoded on the capture thread while the
	// UI reads and exports on its own thread. Held in a shared_ptr so the widget state stays movable.
	std::shared_ptr<std::mutex> dataMutex = std::make_shared<std::mutex>();
	bool keepRawPackets = false;         // only for debugging: holding every packet makes a long session's memory grow
	uint32_t loginSerial = 0;            // +1 each time a login is seen; a new login means new full lists
	bool discsLoaded = false, enginesLoaded = false, agentsLoaded = false;
	uint32_t pendingChanges = 0;         // changes merged from sync notifications since the last save
	std::optional<std::string> detectedRegion;// region whose key decrypted the login, once known
	// Which integer list of the item sync block removes discs (1) or W-Engines (2), learned from unambiguous
	// removals. Reliquary Archiver reads Star Rail's del_relic_list / del_equipment_list by name; ZZZ's names are
	// obfuscated, so the role of each list is inferred instead.
	std::unordered_map<int32_t, int> removalListKind;

	[[nodiscard]] bool loginComplete() const {
		return discsLoaded && enginesLoaded && agentsLoaded;
	}

#ifdef _WIN32
	std::unique_ptr<pcap::PktMonDevice> device;
#else
	pcpp::PcapLiveDevice *device = nullptr;
#endif
	std::jthread captureThread;

	inline void storeCapturePacketsToFile() {
		std::ofstream file("captured_packets.json");
		if (!file.is_open()) {
			debug::log("Failed to open file for writing.");
			return;
		}
		std::string buffer;
		auto ec = glz::write_json(capturedPackets, buffer);
		if (ec) {
			debug::log("Failed to serialize packets: {}", static_cast<int>(ec));
			return;
		}
		file << buffer;
		debug::log("Captured packets stored to captured_packets.json");
		file.close();
	}

	inline void loadCapturePacketsFromFile() {
		std::ifstream file("captured_packets.json");
		if (!file.is_open()) {
			debug::log("Failed to open file for reading.");
			return;
		}
		std::string buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		auto ec = glz::read_json(capturedPackets, buffer);
		if (ec) {
			debug::log("Failed to deserialize packets: {}", static_cast<int>(ec));
			return;
		}
		debug::log("Captured packets loaded from captured_packets.json");
		file.close();

		for (const auto &packet: capturedPackets.packets) {
			processPacket(packet.data, packet.timestamp, packet.direction);
		}
	}

	// Tries the remembered region key first, then every region in datamine.json. The right key is the one whose
	// decrypted token response yields the RSA-encrypted server key (a wrong key gives garbage that never does).
	inline bool detectRegionAndServerKey(auto body) {
		auto &datamine = serialization::Datamine::get();
		std::vector<std::pair<std::string, uint64_t>> candidates;
		if (crypto::xorpad::initialSeed) candidates.emplace_back("", *crypto::xorpad::initialSeed);
		for (const auto &[region, seed]: datamine.xorSeeds) {
			uint64_t value = std::stoull(seed, nullptr, 16);
			if (!crypto::xorpad::initialSeed || value != *crypto::xorpad::initialSeed) candidates.emplace_back(region, value);
		}
		auto previous = crypto::xorpad::initialSeed;
		for (const auto &[region, seed]: candidates) {
			crypto::xorpad::initialSeed = seed;
			auto decrypted = session.decryptBody(body);
			try {
				session.serverRandKey = session.extractServerRandKey(std::span<const uint8_t>{decrypted});
			} catch (const std::exception &) {
				continue;
			}
			std::string name = region;
			if (name.empty()) {
				std::string hex = std::format("{:016X}", seed);
				for (const auto &[r, s]: datamine.xorSeeds)
					if (s == hex) name = r;
			}
			{
				std::scoped_lock lock{*dataMutex};
				detectedRegion = name;
			}
			debug::log("dispatch: login decrypted with the {} key; server_rand_key={:016X}", name, *session.serverRandKey);
			return true;
		}
		crypto::xorpad::initialSeed = previous;
		debug::log("dispatch: no region key decrypted the login response");
		return false;
	}

	// Repeated integer field values, packed or not.
	static void readUints(const google::protobuf::UnknownField &f, std::vector<uint64_t> &out) {
		if (f.type() == google::protobuf::UnknownField::TYPE_VARINT) {
			out.push_back(f.varint());
		} else if (f.type() == google::protobuf::UnknownField::TYPE_LENGTH_DELIMITED) {
			const auto bytes = f.length_delimited();
			uint64_t value = 0;
			int shift = 0;
			for (unsigned char c: bytes) {
				value |= static_cast<uint64_t>(c & 0x7F) << shift;
				if (c & 0x80) {
					shift += 7;
					if (shift > 63) return;// malformed
				} else {
					out.push_back(value);
					value = 0;
					shift = 0;
				}
			}
		}
	}

	// Merges one inventory sync notification: changed or new records replace ours (discs and W-Engines by UID,
	// agents by ID). A removed-items list is recognised as an integer list in the item block whose values are all
	// UIDs we hold of exactly one kind (discs or W-Engines) and none of which came back as changed records.
	inline void applySync(const google::protobuf::UnknownFieldSet &fields, const serialization::SyncLayout &sync) {
		std::vector<data::DiscInfo> discUpd;
		std::vector<data::WeaponInfo> weaponUpd;
		std::vector<data::AgentInfo> agentUpd;
		std::unordered_map<int32_t, std::vector<uint64_t>> uidLists;

		auto readAgents = [&](const google::protobuf::UnknownFieldSet &block) {
			for (int i = 0; i < block.field_count(); ++i) {
				const auto &f = block.field(i);
				if (f.number() != sync.avatarListField || f.type() != google::protobuf::UnknownField::TYPE_LENGTH_DELIMITED) continue;
				google::protobuf::UnknownFieldSet nested;
				if (nested.ParseFromString(f.length_delimited())) agentUpd.push_back(data::AgentInfo::fromUFS(nested));
			}
		};

		for (int i = 0; i < fields.field_count(); ++i) {
			const auto &top = fields.field(i);
			if (top.type() != google::protobuf::UnknownField::TYPE_LENGTH_DELIMITED) continue;
			if (top.number() != sync.itemField && top.number() != sync.avatarField) continue;
			google::protobuf::UnknownFieldSet block;
			if (!block.ParseFromString(top.length_delimited())) continue;
			if (top.number() == sync.avatarField) readAgents(block);
			if (top.number() != sync.itemField) continue;
			for (int j = 0; j < block.field_count(); ++j) {
				const auto &f = block.field(j);
				if (f.number() == sync.discField && f.type() == google::protobuf::UnknownField::TYPE_LENGTH_DELIMITED) {
					google::protobuf::UnknownFieldSet nested;
					if (nested.ParseFromString(f.length_delimited())) discUpd.push_back(data::DiscInfo::fromUFS(nested));
				} else if (f.number() == sync.weaponField && f.type() == google::protobuf::UnknownField::TYPE_LENGTH_DELIMITED) {
					google::protobuf::UnknownFieldSet nested;
					if (nested.ParseFromString(f.length_delimited())) weaponUpd.push_back(data::WeaponInfo::fromUFS(nested));
				} else if (std::ranges::find(sync.itemUidLists, f.number()) != sync.itemUidLists.end()) {
					readUints(f, uidLists[f.number()]);
				}
			}
		}

		uint32_t changes = 0;
		size_t removedDiscs = 0, removedWeapons = 0;
		{
			std::scoped_lock lock{*dataMutex};
			if (!loginComplete()) return;// nothing to merge into yet; the login lists will be complete anyway

			for (auto &d: discUpd) {
				auto it = std::ranges::find(discs, d.uid, &data::DiscInfo::uid);
				if (it != discs.end()) *it = std::move(d);
				else discs.push_back(std::move(d));
				++changes;
			}
			for (auto &w: weaponUpd) {
				auto it = std::ranges::find(engines, w.uid, &data::WeaponInfo::uid);
				if (it != engines.end()) *it = std::move(w);
				else engines.push_back(std::move(w));
				++changes;
			}
			for (auto &a: agentUpd) {
				auto it = std::ranges::find(agents, a.id, &data::AgentInfo::id);
				if (it != agents.end()) *it = std::move(a);
				else agents.push_back(std::move(a));
				++changes;
			}

			std::unordered_set<uint64_t> discUids, weaponUids, changedUids;
			for (const auto &d: discs) discUids.insert(d.uid);
			for (const auto &w: engines) weaponUids.insert(w.uid);
			for (const auto &d: discUpd) changedUids.insert(d.uid);
			for (const auto &w: weaponUpd) changedUids.insert(w.uid);
			for (const auto &[number, values]: uidLists) {
				if (values.empty()) continue;
				bool allDiscs = true, allWeapons = true, anyChanged = false;
				for (auto v: values) {
					allDiscs = allDiscs && discUids.contains(v);
					allWeapons = allWeapons && weaponUids.contains(v);
					anyChanged = anyChanged || changedUids.contains(v);
				}
				if (anyChanged) continue;// changed items come back as records: this is not a removal list
				int kind = 0;
				if (allDiscs && !allWeapons) kind = 1;
				else if (allWeapons && !allDiscs) kind = 2;
				else if (allDiscs && allWeapons) {
					auto learned = removalListKind.find(number);// both kinds hold these UIDs: use what this list did before
					if (learned != removalListKind.end()) kind = learned->second;
				}
				if (kind == 0) continue;
				removalListKind[number] = kind;
				allDiscs = kind == 1;
				std::unordered_set<uint64_t> gone(values.begin(), values.end());
				if (allDiscs) {
					removedDiscs += std::erase_if(discs, [&](const data::DiscInfo &d) { return gone.contains(d.uid); });
				} else {
					removedWeapons += std::erase_if(engines, [&](const data::WeaponInfo &w) { return gone.contains(w.uid); });
				}
				debug::log("sync: field {} removed {} {}", number, values.size(), allDiscs ? "discs" : "W-Engines");
			}
			changes += static_cast<uint32_t>(removedDiscs + removedWeapons);
			pendingChanges += changes;
		}
		if (changes == 0) return;
		debug::log("sync: {} discs, {} W-Engines, {} agents updated; {} discs, {} W-Engines removed", discUpd.size(), weaponUpd.size(), agentUpd.size(), removedDiscs, removedWeapons);
		onEventUpdate.notify();
	}

	inline void processMessageBody(std::span<const uint8_t> messageBytes, int64_t unixSeconds) {
		if (messageBytes.size() < KCP::MessageHeader::size) return;
		KCP::MessageHeader messageHeader = KCP::MessageHeader::fromBytes(messageBytes);

		auto body = messageBytes
				  | std::views::drop(KCP::MessageHeader::size + messageHeader.headLength)
				  | std::views::take(messageHeader.bodyLength);

		auto &datamine = serialization::Datamine::get();

		// Login: the token response is the only packet encrypted with the region key alone. Every login starts a new
		// session key, so reset and try the region keys (the remembered one first) until one decrypts it.
		if (messageHeader.commandId == datamine.cmdPlayerGetTokenScRsp) {
			session = crypto::Session{};
			if (detectRegionAndServerKey(body)) {
				std::scoped_lock lock{*dataMutex};
				++loginSerial;
				discsLoaded = enginesLoaded = agentsLoaded = false;
				pendingChanges = 0;
			}
			onEventUpdate.notify();
			return;
		}
		if (!crypto::xorpad::initialSeed) return;// no login seen yet

		auto decrypted = session.decryptBody(body);

		if (session.serverRandKey && !session.sessionPadReady && messageHeader.bodyLength >= 32) {
			session.deriveSessionKey(body, unixSeconds);
			if (session.sessionPadReady) {
				decrypted = session.decryptBody(body);
			}
			onEventUpdate.notify();
		}

		if (decrypted.empty()) return;
		auto fields = std::make_shared<google::protobuf::UnknownFieldSet>();
		if (!fields->ParseFromArray(decrypted.data(), static_cast<int>(decrypted.size()))) {
			debug::log("Failed to parse decrypted body as protobuf for cmd {} ({} bytes)", messageHeader.commandId, decrypted.size());
			return;
		}
		crypto::xorProtoFields(*fields, serialization::Proto::get().getEntryById(messageHeader.commandId));
		debug::log("cmd {} ({} bytes):", messageHeader.commandId, decrypted.size());
		if (keepRawPackets) parsedPackets.emplace_back(fields);

		if (messageHeader.commandId == datamine.cmdGetEquipDataScRsp) {
			// Full list at login: replace what we have (a second login must not duplicate everything).
			std::vector<data::DiscInfo> list;
			for (int i = 0; i < fields->field_count(); ++i) {
				const auto &f = fields->field(i);
				if (f.number() != datamine.equipData.discs) continue;
				google::protobuf::UnknownFieldSet nested;
				if (nested.ParseFromString(f.length_delimited())) list.push_back(data::DiscInfo::fromUFS(nested));
			}
			size_t count = list.size();
			{
				std::scoped_lock lock{*dataMutex};
				discs = std::move(list);
				discsLoaded = true;
			}
			onEventUpdate.notify();
			debug::log("  decoded {} discs", count);
		}

		if (messageHeader.commandId == datamine.cmdGetWeaponDataScRsp) {
			// Full list at login: replace what we have (a second login must not duplicate everything).
			std::vector<data::WeaponInfo> list;
			for (int i = 0; i < fields->field_count(); ++i) {
				const auto &f = fields->field(i);
				if (f.number() != datamine.weaponData.weapons) continue;
				google::protobuf::UnknownFieldSet nested;
				if (nested.ParseFromString(f.length_delimited())) list.push_back(data::WeaponInfo::fromUFS(nested));
			}
			size_t count = list.size();
			{
				std::scoped_lock lock{*dataMutex};
				engines = std::move(list);
				enginesLoaded = true;
			}
			onEventUpdate.notify();
			debug::log("  decoded {} weapons", count);
		}

		if (messageHeader.commandId == datamine.cmdGetAvatarDataScRsp) {
			// Full list at login: replace what we have (a second login must not duplicate everything).
			std::vector<data::AgentInfo> list;
			for (int i = 0; i < fields->field_count(); ++i) {
				const auto &f = fields->field(i);
				if (f.number() != datamine.agentData.agents) continue;
				google::protobuf::UnknownFieldSet nested;
				if (nested.ParseFromString(f.length_delimited())) list.push_back(data::AgentInfo::fromUFS(nested));
			}
			size_t count = list.size();
			{
				std::scoped_lock lock{*dataMutex};
				agents = std::move(list);
				agentsLoaded = true;
			}
			onEventUpdate.notify();
			debug::log("  decoded {} avatars", count);
		}

		const auto &sync = serialization::SyncLayout::get();
		if (sync.valid() && messageHeader.commandId == sync.cmd) {
			applySync(*fields, sync);
		}
	}

	inline void processPacket(std::span<const uint8_t> data, int64_t unixSeconds, serialization::Direction direction) {
		auto messages = kcp.receive(data, direction);
		for (auto &message: messages) {
			processMessageBody(message, unixSeconds);
		}
	}

	inline void processRawPacket(pcpp::RawPacket *rawPacket) {
		pcpp::Packet parsedPacket(rawPacket);
		auto *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
		if (!udpLayer) return;
		if (udpLayer->getSrcPort() != 20501 && udpLayer->getDstPort() != 20501) return;

		auto data = std::span(udpLayer->getLayerPayload(), udpLayer->getLayerPayloadSize());
		if (data.empty()) return;

		bool outgoing = udpLayer->getDstPort() == 20501;
		auto direction = outgoing ? serialization::Direction::outgoing : serialization::Direction::incoming;
		processPacket(data, rawPacket->getPacketTimeStamp().tv_sec, direction);

		if (keepRawPackets) {
			capturedPackets.packets.emplace_back(serialization::Packet{
				.direction = direction,
				.timestamp = rawPacket->getPacketTimeStamp().tv_sec,
				.data = std::vector<uint8_t>(data.begin(), data.end()),
			});
		}
	}

	inline void listen() {
		if (captureThread.joinable()) return;

#ifdef _WIN32
		device = std::make_unique<pcap::PktMonDevice>();
		if (!device->open()) {
			debug::log("Failed to open PktMon device (are you running as administrator?)");
			device.reset();
			return;
		}

		if (!device->addUdpPortFilter(20501)) {
			debug::log("Failed to set PktMon capture filter, capturing all traffic");
		}

		debug::log("Capture started");

		captureThread = std::jthread([this]() {
			auto result = device->receivePackets(
				[this](const pcap::PktMonDevice::RawPacketVector &packetVec) {
					for (auto *rawPacket: packetVec) {
						processRawPacket(rawPacket);
					}
				},
				0,
				64
			);
			if (result.status != pcap::PktMonDevice::ReceiveResult::Status::completed) {
				debug::log("Capture stopped: {} (code {})", result.error, result.errorCode);
			}
		});
#else
		device = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName("any");
		if (!device) {
			debug::log("Failed to find a capture device (are you running as root or with CAP_NET_RAW?)");
			return;
		}
		pcpp::PcapLiveDevice::DeviceConfiguration config{
			pcpp::PcapLiveDevice::DeviceMode::Normal,
		};
		if (!device->open(config)) {
			debug::log("Failed to open capture device (are you running as root or with CAP_NET_RAW?)");
			device = nullptr;
			return;
		}
		pcpp::PortFilter portFilter(20501, pcpp::SRC_OR_DST);
		pcpp::ProtoFilter protoFilter(pcpp::UDP);
		pcpp::AndFilter filter;
		filter.addFilter(&portFilter);
		filter.addFilter(&protoFilter);
		if (!device->setFilter(filter)) {
			debug::log("Failed to set capture filter, capturing all traffic");
		}

		debug::log("Capture started");

		captureThread = std::jthread([this]() {
			device->startCapture(
				[this](pcpp::RawPacket *rawPacket, pcpp::PcapLiveDevice *, void *) {
					processRawPacket(rawPacket);
				},
				nullptr
			);
		});
#endif
	}

	inline void stop() {
#ifdef _WIN32
		if (!device || !device->isOpened()) return;
		device->stopReceive();
#else
		if (!device || !device->isOpened()) return;
		device->stopCapture();
#endif
		if (captureThread.joinable()) {
			captureThread.join();
		}
#ifdef _WIN32
		device->close();
		device.reset();
#else
		device->close();
		device = nullptr;
#endif
		debug::log("Capture stopped");
		// this->storeCapturePacketsToFile();
	}
};
