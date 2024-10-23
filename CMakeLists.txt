cmake_minimum_required(VERSION 3.10)

# Establecer nombre de proyecto
project(ProjectEPM)

# Acceso a librerías
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Añade los directorios de encabezados de Sodium y OpenSSL
include_directories(${SODIUM_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})

# Crear librería
add_library(epm STATIC
  src/file/man.c
  src/file/basics.c
  src/file/mod.c
  src/crypto/crypto.c
  src/input/input.c
)

# Definir directorios de inclusión para la librería
target_include_directories(epm PUBLIC include)

# Enlazar librerías con la librería estática
target_link_libraries(epm PRIVATE OpenSSL::Crypto ${SODIUM_LIBRARIES})

# Indicar punto de partida del programa
add_executable(main main.c)

# Enlazar la librería estática con el ejecutable
target_link_libraries(main PRIVATE epm)
