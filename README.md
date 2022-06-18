# Memory integrity check

Retrieve all non-writable sections with `IMAGE_SCN_MEM_WRITE` flag in specified module then hash original bytes of section via CRC32 instruction \
Repeat steps in loop and compare new bytes of section via `integrity::check::compare_checksums`

# Example for usage
```cpp
std::int32_t main(int, char **)
{
    integrity::check check = integrity::check();

    while (true)
    {
        const std::vector<integrity::check::section> &sections = check.compare_checksums(check.retrieve_sections());

        if (!sections.size())
            std::cout << "all sections are good" << std::endl;

        for (const integrity::check::section &section : sections)
            std::cout << section.name << " section has been changed" << std::endl;

        std::this_thread::sleep_for(500ms);
    }

    return EXIT_SUCCESS;
}
```

# POC
![](media/poc.gif)