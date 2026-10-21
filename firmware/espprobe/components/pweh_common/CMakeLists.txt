idf_component_register(SRCS "../../../common/cobs.c" "../../../common/crc32.c"
    "../../../common/protocol.c" "../../../common/tlv.c" "../../../common/session.c"
    INCLUDE_DIRS "../../../common/include")
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
