@echo off

set toolchain=%~1
set project=%~2
set directory=%~dp0%project%

if not exist %directory%\%project%.c (
  echo Error: Project directory '%~dp0%project%' does not exist. 1>&2
  exit /b 1
)

set source=%directory%\%project%.c
set output=%directory%-%toolchain%-mint.exe

if '%toolchain%' == 'clang' (
  clang -O3 -std=c89 -mcrc32 %source% -o %output%
  exit /b %errorlevel%
)

if '%toolchain%' == 'gcc' (
  gcc -s -O3 -std=c89 -mcrc32 %source% -o %output%
  exit /b %errorlevel%
)

if '%toolchain%' == 'msvc' (
  pushd %~dp0 && cl /O2 /std:c11 %source% /Fe:%output%
  popd && exit /b %errorlevel%
)

echo Error: Unknown toolchain '%toolchain%', try to use 'msvc', 'gcc' or 'clang'. 1>&2
exit /b 1
