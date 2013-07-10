cmake_minimum_required(VERSION 2.8)

SET(DynamoRIO_DIR "~/dynamorio/exports/cmake")
find_package(DynamoRIO)

add_library(emfile SHARED emfile.c ../common.c)
configure_DynamoRIO_client(emfile)

use_DynamoRIO_extension(emfile drwrap)
