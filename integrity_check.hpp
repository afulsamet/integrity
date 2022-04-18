#pragma once

#include <windows.h>
#include <intrin.h>

#include <vector>
#include <stdexcept>

namespace integrity {
	class check {
	public:
		check(const char* module = nullptr) {
			if (this->module = reinterpret_cast<std::uintptr_t>(GetModuleHandle(module)))
				this->sections = this->retrieve_sections(); // Cache all sections
		}

	private:
		std::uintptr_t module = std::uintptr_t();

	private:
		static const std::uint32_t crc32(void* data, std::size_t size) noexcept {
			std::uint32_t result = 0;

			for (std::size_t index = 0; index < size; ++index)
				result = _mm_crc32_u8(result, reinterpret_cast<std::uint8_t*>(data)[index]);

			return result;
		}

	public:
		struct section {
			std::uint8_t* name;
			void* address;
			std::size_t size;
			std::size_t characteristics;
			std::uint32_t checksum;

			section() : name(nullptr), address(nullptr), size(std::size_t()), characteristics(std::size_t()), checksum(std::uint32_t()) {}

			section(std::uint8_t* name, void* address, std::size_t size, std::size_t characteristics) : name(name), address(address), size(size), characteristics(characteristics) {
				this->checksum = check::crc32(this->address, this->size);
			}
		};

		/// <summary>
		/// Retrieve all non-writable sections from specified module
		/// </summary>
		std::vector<section> retrieve_sections() const noexcept {
			std::vector<section> result = {};

			PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(this->module + reinterpret_cast<PIMAGE_DOS_HEADER>(this->module)->e_lfanew);
			if (nt_headers == nullptr) return result;

			PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
			for (std::uint16_t index = 0; index < nt_headers->FileHeader.NumberOfSections; index++, section++)
				if ((section->Characteristics & IMAGE_SCN_MEM_WRITE) == false)
					result.push_back({ section->Name, reinterpret_cast<void*>(this->module + section->VirtualAddress), section->Misc.VirtualSize, section->Characteristics });

			return result;
		}

		/// <summary>
		/// Compare CRC32 checksum of cached sections with another sections
		/// </summary>
		/// <returns>If there is a change in sections, returns changed sections</returns>
		std::vector<section> compare_checksums(const std::vector<section>& sections) const noexcept {
			std::vector<section> result = {};

			for (std::size_t index = 0; index < this->sections.size(); index++)
				if (this->sections[index].checksum != sections[index].checksum)
					result.push_back(sections[index]);

			return result;
		}

	private:
		std::vector<section> sections = {};
	};
}