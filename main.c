#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <byteswap.h>

#include <snappy-c.h>

#include "protos/demo.pb-c.h"
#include "protos/netmessages.pb-c.h"

#define u8 uint8_t
#define i8 int8_t
#define u16 uint16_t
#define i16 int16_t
#define u32 uint32_t
#define i32 int32_t
#define u64 uint64_t
#define i64 int64_t

#define DEMO_COMMAND_ERROR -1
#define DEMO_COMMAND_STOP 0
#define DEMO_COMMAND_FILE_HEADER 1
#define DEMO_COMMAND_FILE_INFO 2
#define DEMO_COMMAND_SYNC_TICK 3
#define DEMO_COMMAND_SEND_TABLES 4
#define DEMO_COMMAND_CLASS_INFO 5
#define DEMO_COMMAND_STRING_TABLES 6
#define DEMO_COMMAND_PACKET 7
#define DEMO_COMMAND_SIGNON_PACKET 8
#define DEMO_COMMAND_CONSOLE_CMD 9
#define DEMO_COMMAND_CUSTOM_DATA 10
#define DEMO_COMMAND_CUSTOM_DATA_CALLBACKS 11
#define DEMO_COMMAND_USER_CMD 12
#define DEMO_COMMAND_FULL_PACKET 13
#define DEMO_COMMAND_SAVE_GAME 14
#define DEMO_COMMAND_MAX 15
#define DEMO_COMMAND_IS_COMPRESSED 112

#define UNUSED(a) (void)a

#define log_info printf
#define log_err printf
#define log_warn printf
#define log_debug printf

#define APP_NAME "demo_parser"

typedef struct DemoPacket
{
    char *data;
    u32 type;
    u32 data_size;
} DemoPacket;

typedef struct Parser
{
    u8 *data;
    size_t data_size;
    size_t pos;

    DemoPacket packet;
    char *uncompressed_buffer;
    size_t uncompressed_buffer_size;
} Parser;

typedef struct DemoHeader
{
    char magic[8];
    u32 summary_offset;
    u32 packet_offset;
} DemoHeader;

//
// Forward declarations
//

static void print_usage();

static void parser_init(Parser *parser);

#define PARSER_NEXT_PACKET_RET_OK 0
#define PARSER_NEXT_PACKET_RET_END 1
#define PARSER_NEXT_PACKET_RET_DECOMPRESS_ERROR 2
#define PARSER_NEXT_PACKET_RET_OOM 3

static int parser_next_packet(Parser *parser, DemoPacket *out_packet);
static u32 parser_read_varint32(Parser *parser);

static u32 read_varint32(const u8 *data, u32 *read);
static const char *demo_command_to_string(int command);

static void demo_header_to_string(DemoHeader header);

static int process_demo_packet(DemoPacket packet);

static size_t min_uint(size_t a, size_t b);
static size_t max_uint(size_t a, size_t b);

//
// Implementations
//

static void demo_header_to_string(DemoHeader header)
{
    log_debug("Magic:          %s\n", header.magic);
    log_debug("Summary offset: %u\n", header.summary_offset);
    log_debug("Packet offset:  %u\n", header.packet_offset);
}

static u32 read_varint32(const u8 *data, u32 *read)
{
    uint32_t result = 0;
    u8 tmp;
    (*read) = 0;
    size_t position = 0;

    do
    {
        assert((*read) < 5);

        tmp = data[position++];
        result |= (uint32_t)(tmp & 0x7F) << (7 * (*read));
        ++(*read);
    } while (tmp & 0x80);

    return result;
}

static void parser_init(Parser *parser)
{
    parser->data = nullptr;
    parser->data_size = 0;
    parser->pos = 0;
    parser->packet.data = nullptr;
    parser->packet.data_size = 0;
    parser->packet.type = 0;
    parser->uncompressed_buffer = nullptr;
    parser->uncompressed_buffer_size = 0;
}

static u32 parser_read_varint32(Parser *parser)
{
    u32 result = 0;
    u32 bytes_read = 0;

    while (true)
    {
        assert(bytes_read < 5);

        const u8 tmp = parser->data[parser->pos];
        result |= (u32)(tmp & 0x7Fu) << (7u * bytes_read);

        ++bytes_read;
        ++(parser->pos);

        if (!(tmp & 0x80u))
        {
            break;
        }
    }

    return result;
}

static int parser_next_packet(Parser *parser, DemoPacket *out_packet)
{
    if (parser->pos >= parser->data_size)
    {
        log_debug("Reached end of stream");
        return PARSER_NEXT_PACKET_RET_END;
    }

    const u32 demo_cmd_raw = parser_read_varint32(parser);
    const u32 demo_cmd = demo_cmd_raw & (~DEMO_COMMAND_IS_COMPRESSED);
    assert(!(demo_cmd & DEMO_COMMAND_IS_COMPRESSED));
    const u32 tick = parser_read_varint32(parser);
    const u32 size = parser_read_varint32(parser);
    const bool is_compressed = demo_cmd_raw & DEMO_COMMAND_IS_COMPRESSED;
    const char *is_compressed_string = (is_compressed) ? "true" : "false";

    log_debug("Type:       %s (%d)\n", demo_command_to_string(demo_cmd), demo_cmd);
    log_debug("Compressed: %s\n", is_compressed_string);
    log_debug("Size:       %u\n", size);
    log_debug("Tick:       %u\n", tick);

    out_packet->type = demo_cmd;

    if (is_compressed)
    {
        char *compressed_data = (char *)(parser->data + parser->pos);
        //
        // TODO: Reuse decompression buffer, resize
        //
        log_debug("Decompressing packet...\n");

        size_t required_size = 0;
        if (snappy_uncompressed_length(compressed_data, size, &required_size) != SNAPPY_OK)
        {
            log_err("Failed to calculate decompressed size\n");
            return PARSER_NEXT_PACKET_RET_DECOMPRESS_ERROR;
        }

        log_debug("Uncompressed size: %zu\n", required_size);

        const size_t min_allocation = 1024 * 1024;

        if (!parser->uncompressed_buffer)
        {
            const size_t alloc_size = max_uint(required_size, min_allocation);
            log_debug("Allocating %zu for uncompressed buffer\n", alloc_size);
            parser->uncompressed_buffer = (char *)malloc(alloc_size);
            if (!parser->uncompressed_buffer)
            {
                log_err("Failed to allocate uncompressed packet buffer\n");
                return PARSER_NEXT_PACKET_RET_OOM;
            }
            parser->uncompressed_buffer_size = alloc_size;
        }

        if (parser->uncompressed_buffer_size < required_size)
        {
            const size_t alloc_size = max_uint(required_size, min_allocation);
            log_debug("Reallocating uncompressed buffer from %zu to %zu\n", parser->uncompressed_buffer_size, alloc_size);
            parser->uncompressed_buffer = (char *)realloc(parser->uncompressed_buffer, alloc_size);
            if (!parser->uncompressed_buffer)
            {
                log_err("Failed to reallocate uncompressed packet buffer\n");
                return PARSER_NEXT_PACKET_RET_OOM;
            }
            parser->uncompressed_buffer_size = alloc_size;
        }

        size_t actual_uncompressed_size = parser->uncompressed_buffer_size;
        const snappy_status status = snappy_uncompress(compressed_data, size, parser->uncompressed_buffer, &actual_uncompressed_size);

        if (status != SNAPPY_OK)
        {
            log_err("Failed to decompresss data. Status: %d\n", status);
            return PARSER_NEXT_PACKET_RET_DECOMPRESS_ERROR;
        }

        out_packet->data = parser->uncompressed_buffer;
        out_packet->data_size = actual_uncompressed_size;
    }
    else
    {
        out_packet->data = (char *)(parser->data + parser->pos);
        out_packet->data_size = size;
    }

    parser->pos += size;

    return PARSER_NEXT_PACKET_RET_OK;
}

static const char *demo_command_to_string(int command)
{
    switch (command)
    {
    case DEMO_COMMAND_ERROR:
        return "Error";
    case DEMO_COMMAND_STOP:
        return "Stop";
    case DEMO_COMMAND_FILE_HEADER:
        return "File Header";
    case DEMO_COMMAND_FILE_INFO:
        return "File Info";
    case DEMO_COMMAND_SYNC_TICK:
        return "Sync Tick";
    case DEMO_COMMAND_SEND_TABLES:
        return "Send Tables";
    case DEMO_COMMAND_CLASS_INFO:
        return "Class Info";
    case DEMO_COMMAND_STRING_TABLES:
        return "String Tables";
    case DEMO_COMMAND_PACKET:
        return "Packet";
    case DEMO_COMMAND_SIGNON_PACKET:
        return "Signon Packet";
    case DEMO_COMMAND_CONSOLE_CMD:
        return "Console Command";
    case DEMO_COMMAND_CUSTOM_DATA:
        return "Custom Data";
    case DEMO_COMMAND_CUSTOM_DATA_CALLBACKS:
        return "Custom Data Callbacks";
    case DEMO_COMMAND_USER_CMD:
        return "User Command";
    case DEMO_COMMAND_FULL_PACKET:
        return "Full Packet";
    case DEMO_COMMAND_SAVE_GAME:
        return "Save Game";
    case DEMO_COMMAND_MAX:
        return "Max (Not valid)";
    default:
        //
        // Fall through
        //
    }
    return "Unknown";
}

int process_demo_packet(DemoPacket packet)
{
    log_debug("Processing packet..\n");
    switch (packet.type)
    {
    case DEMO_COMMAND_FILE_HEADER:
    {
        CDemoFileHeader *file_header = cdemo_file_header__unpack(nullptr, packet.data_size, (u8 *)packet.data);
        log_info("File header:\n");
        log_info("  Client name: %s\n", file_header->client_name);
        log_info("  Demo file stamp: %s\n", file_header->demo_file_stamp);
        log_info("  Game directory: %s\n", file_header->game_directory);
        log_info("  Map name: %s\n", file_header->map_name);
        log_info("  Server name: %s\n", file_header->server_name);
        cdemo_file_header__free_unpacked(file_header, nullptr);
        break;
    }
    case DEMO_COMMAND_PACKET:
    {
        CDemoPacket *proto = cdemo_packet__unpack(nullptr, packet.data_size, (u8 *)packet.data);
        log_info("Packet:\n");
        log_info("  Has data: %s\n", proto->has_data ? "true" : "false");
        cdemo_packet__free_unpacked(proto, nullptr);
        break;
    }
    case DEMO_COMMAND_CLASS_INFO:
    {
        CDemoClassInfo *proto = cdemo_class_info__unpack(nullptr, packet.data_size, (u8 *)packet.data);
        log_info("Class Info:\n");
        for (size_t i = 0; i < proto->n_classes; i++)
        {
            log_info("  Class #%zu\n", i);
            const CDemoClassInfo__ClassT *class_info = proto->classes[i];
            if (class_info->has_class_id)
            {
                log_info("    Class ID: %d\n", class_info->class_id);
            }
            log_info("    Network name: %s\n", class_info->network_name);
            log_info("    Table name: %s\n", class_info->table_name);
        }
        break;
    }
    case DEMO_COMMAND_SEND_TABLES:
    {
        CDemoSendTables *proto = cdemo_send_tables__unpack(nullptr, packet.data_size, (u8 *)packet.data);

        u32 bytes_read = 0;
        const u32 data_size = read_varint32(proto->data.data, &bytes_read);
        const u8* data = proto->data.data + bytes_read;

        CSVCMsgFlattenedSerializer *flattened_serializer = csvcmsg__flattened_serializer__unpack(nullptr, data_size, data);

        log_info("Send Tables:\n");

        if (flattened_serializer)
        {
            log_info("  Field count:      %zu\n", flattened_serializer->n_fields);
            log_info("  Serializer count: %zu\n", flattened_serializer->n_serializers);
            log_info("  Symbol count:     %zu\n", flattened_serializer->n_symbols);

            for (size_t i = 0; i < flattened_serializer->n_serializers; i++)
            {
                ProtoFlattenedSerializerT *serializer = flattened_serializer->serializers[i];
                if (serializer->has_serializer_name_sym)
                {
                    log_info("  serializer_name_sym: %d\n", serializer->serializer_name_sym);
                }
                if (serializer->has_serializer_version)
                {
                    log_info("  serializer_version: %d\n", serializer->serializer_version);
                }
            }
        }
        else
        {
            log_err("Failed to extract flattened serializer\n");
        }
        break;
    }
    default:
        log_debug("Unsupported packet type. Skipping\n");
    }
    return 0;
}

static size_t min_uint(size_t a, size_t b)
{
    return (a < b) ? a : b;
}

static size_t max_uint(size_t a, size_t b)
{
    return (a < b) ? a : b;
}

static void print_usage()
{
    printf(APP_NAME " <input_demo_file>\n");
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        print_usage();
        return 1;
    }

    const char* demo_path = argv[1];
    FILE *demo_file = fopen(demo_path, "rb");

    if (!demo_file)
    {
        printf("Failed to open demo file\n");
        return 1;
    }

    fseek(demo_file, 0, SEEK_END);
    const long file_size = ftell(demo_file);
    fseek(demo_file, 0, SEEK_SET);

    u8 *buffer = (u8 *)malloc(file_size);

    if (fread(buffer, file_size, 1, demo_file) != 1)
    {
        printf("Failed to read demo file\n");
    }

    fclose(demo_file);

    DemoHeader *demo_header = (DemoHeader *)buffer;
    demo_header_to_string(*demo_header);

    Parser parser;
    parser_init(&parser);

    parser.data = buffer;
    parser.data_size = file_size;
    parser.pos = sizeof(DemoHeader);

    int ret_code = PARSER_NEXT_PACKET_RET_END;
    do
    {
        DemoPacket packet;
        ret_code = parser_next_packet(&parser, &packet);

        const double percent = ((double)parser.pos / (double)parser.data_size) * 100.0;
        log_debug("== %zu / %zu (%f%%) ==\n", parser.pos, parser.data_size, percent);

        switch (ret_code)
        {
        case PARSER_NEXT_PACKET_RET_OK:
            log_info("Packet parsed. Type: %s (%d)\n", demo_command_to_string(packet.type), packet.type);
            process_demo_packet(packet);
            break;
        case PARSER_NEXT_PACKET_RET_DECOMPRESS_ERROR:
            log_err("Failed to decompress demo packet. Skipping\n");
            break;
        case PARSER_NEXT_PACKET_RET_OOM:
            log_err("Out of memory. Terminating process\n");
            exit(EXIT_FAILURE);
            break;
        default:
            //
            // Fall through
            //
        }
    } while (ret_code != PARSER_NEXT_PACKET_RET_END);

    free(buffer);

    return 0;
}
