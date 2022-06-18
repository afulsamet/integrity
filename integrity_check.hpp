#pragma once

#include <windows.h>
#include <nmmintrin.h>

#include <vector>

namespace integrity
{
    class check
    {
    public:
        check(const char *module = nullptr)
            : module(this->get_module_handle_as(module)), sections(this->retrieve_sections()) {}

    public:
        struct section
        {
            std::uint8_t *name = {};
            void *address = {};
            std::size_t size = {};
            std::size_t characteristics = {};
            std::uint32_t checksum = {};

            const bool operator==(const section &other) const noexcept
            {
                return this->checksum == other.checksum;
            }
        };

        /// <summary>
        /// Retrieve all non-writable sections from specified module
        /// </summary>
        std::vector<section> retrieve_sections() const noexcept
        {
            std::vector<section> result = {};

            PIMAGE_NT_HEADERS nt_headers = this->get_nt_headers(this->get_dos_header());
            PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);

            for (std::uint16_t index = {}; index < nt_headers->FileHeader.NumberOfSections; index++, section++)
                if ((section->Characteristics & IMAGE_SCN_MEM_WRITE) == false)
                    if (void *address = this->get_address_from_va<void *>(section->VirtualAddress))
                        result.push_back({section->Name, address, section->Misc.VirtualSize, section->Characteristics, this->crc32(address, section->Misc.VirtualSize)});

            return result;
        }

        /// <summary>
        /// Compare CRC32 checksum of cached sections with another sections
        /// </summary>
        /// <returns>If there is a change in sections, returns changed sections</returns>
        std::vector<section> compare_checksums(const std::vector<section> &sections) const noexcept
        {
            std::vector<section> result = {};

            for (std::size_t index = {}; index < this->sections.size(); index++)
                if (!(this->sections[index] == sections[index]))
                    result.push_back(sections[index]);

            return result;
        }

    private:
        std::uintptr_t module = {};

        const PIMAGE_DOS_HEADER get_dos_header() const noexcept
        {
            return reinterpret_cast<PIMAGE_DOS_HEADER>(this->module);
        }

        const PIMAGE_NT_HEADERS get_nt_headers(const PIMAGE_DOS_HEADER dos_header) const noexcept
        {
            return reinterpret_cast<PIMAGE_NT_HEADERS>(this->module + dos_header->e_lfanew);
        }

        template <typename type = std::uintptr_t>
        const type get_address_from_va(std::uintptr_t virtual_address) const noexcept
        {
            return reinterpret_cast<type>(this->module + virtual_address);
        }

    private:
        static const HMODULE get_module_handle(const char *module = nullptr) noexcept
        {
            return GetModuleHandle(module);
        }

        template <typename type = std::uintptr_t>
        static const type get_module_handle_as(const char *module = nullptr) noexcept
        {
            return reinterpret_cast<type>(check::get_module_handle(module));
        }

    private:
        /// <summary>
        /// WARNING: With GCC must be compiled separately with -msse4.2 flag
        /// </summary>
        static const std::uint32_t crc32(void *data, std::size_t size) noexcept
        {
            std::uint32_t result = {};

            for (std::size_t index = {}; index < size; ++index)
                result = __builtin_ia32_crc32qi(result, reinterpret_cast<std::uint8_t *>(data)[index]);

            return result;
        }

    private:
        std::vector<section> sections = {};
    };
}