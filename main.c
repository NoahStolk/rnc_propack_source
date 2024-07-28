#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <sys/stat.h>
#else
#include <direct.h>
#endif

#ifndef _countof
#ifndef __cplusplus
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#else
extern "C++" {
    template <typename _CountofType, size_t _SizeOfArray> char(*__countof_helper(UNALIGNED _CountofType(&_Array)[_SizeOfArray]))[_SizeOfArray];
#define _countof(_Array) sizeof(*__countof_helper(_Array))
}
#endif
#endif

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

typedef struct vars_s
{
    uint16 enc_key;
    uint16 dict_size;
    uint32 method;
    uint32 input_size;
    uint32 file_size;

    // inner
    uint32 packed_size;
    uint32 processed_size;
    uint16 bit_count;
    uint16 match_count;
    uint16 match_offset;
    uint32 bit_buffer;

    uint16 unpacked_crc;
    uint16 unpacked_crc_real;
    uint16 packed_crc;

    uint8* mem1;
    uint8* pack_block_start;

    uint8* decoded;
    uint8* window;

    size_t read_start_offset;
    uint8* input;
    uint8* output;
    size_t input_offset;
    size_t output_offset;
} vars_t;

enum error_codes
{
    error_none = 0,
    error_corrupted_input_data = 4,
    error_crc_check_failed = 5,
    error_wrong_rnc_header = 6,
    error_wrong_rnc_header_2 = 7,
    error_decryption_key_required = 10,
    error_no_rnc_archives_were_found = 11
};

#define RNC_SIGN 0x524E43 // RNC
#define RNC_HEADER_SIZE 0x12
#define MAX_BUF_SIZE 0x1E00000

static const uint16 crc_table[] = {
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
};

uint8 read_byte(const uint8* buf, size_t* offset)
{
    return buf[(*offset)++];
}

uint16 read_word_be(const uint8* buf, size_t* offset)
{
    const uint8 b1 = read_byte(buf, offset);
    const uint8 b2 = read_byte(buf, offset);

    return b1 << 8 | b2;
}

uint32 read_dword_be(const uint8* buf, size_t* offset)
{
    const uint16 w1 = read_word_be(buf, offset);
    const uint16 w2 = read_word_be(buf, offset);

    return w1 << 16 | w2;
}

void read_buf(uint8* dest, const uint8* source, size_t* offset, const int size)
{
    memmove(dest, &source[*offset], size);
    *offset += size;
}

void write_buf(uint8* dest, size_t* offset, const uint8* source, const int size)
{
    memmove(&dest[*offset], source, size);
    *offset += size;
}

uint16 crc_block(const uint8* buf, size_t offset, int size)
{
    uint16 crc = 0;

    while (size--)
    {
        crc ^= read_byte(buf, &offset);
        crc = crc >> 8 ^ crc_table[crc & 0xFF];
    }

    return crc;
}

void ror_w(uint16* x)
{
    if (*x & 1)
        *x = 0x8000 | *x >> 1;
    else
        *x >>= 1;
}

vars_t* init_vars(void)
{
    vars_t* v = malloc(sizeof(vars_t));
    v->enc_key = 0;
    v->unpacked_crc_real = 0;
    v->dict_size = 0x8000;

    v->read_start_offset = 0;
    v->input_offset = 0;
    v->output_offset = 0;

    return v;
}

uint8 read_source_byte(vars_t* v)
{
    if (v->pack_block_start == &v->mem1[0xFFFD])
    {
        int left_size = v->file_size - v->input_offset;

        int size_to_read;
        if (left_size <= 0xFFFD)
            size_to_read = left_size;
        else
            size_to_read = 0xFFFD;

        v->pack_block_start = v->mem1;

        read_buf(v->pack_block_start, v->input, &v->input_offset, size_to_read);

        if (left_size - size_to_read > 2)
            left_size = 2;
        else
            left_size -= size_to_read;

        read_buf(&v->mem1[size_to_read], v->input, &v->input_offset, left_size);
        v->input_offset -= left_size;
    }

    return *v->pack_block_start++;
}

uint32 input_bits_m2(vars_t* v, short count)
{
    uint32 bits = 0;

    while (count--)
    {
        if (!v->bit_count)
        {
            v->bit_buffer = read_source_byte(v);
            v->bit_count = 8;
        }

        bits <<= 1;

        if (v->bit_buffer & 0x80)
            bits |= 1;

        v->bit_buffer <<= 1;
        v->bit_count--;
    }

    return bits;
}

void decode_match_count(vars_t* v)
{
    v->match_count = input_bits_m2(v, 1) + 4;

    if (input_bits_m2(v, 1))
        v->match_count = (v->match_count - 1 << 1) + input_bits_m2(v, 1);
}

void decode_match_offset(vars_t* v)
{
    v->match_offset = 0;
    if (input_bits_m2(v, 1))
    {
        v->match_offset = input_bits_m2(v, 1);

        if (input_bits_m2(v, 1))
        {
            v->match_offset = v->match_offset << 1 | input_bits_m2(v, 1) | 4;

            if (!input_bits_m2(v, 1))
                v->match_offset = v->match_offset << 1 | input_bits_m2(v, 1);
        }
        else if (!v->match_offset)
            v->match_offset = input_bits_m2(v, 1) + 2;
    }

    v->match_offset = (v->match_offset << 8 | read_source_byte(v)) + 1;
}

void write_decoded_byte(vars_t* v, const uint8 b)
{
    if (&v->decoded[0xFFFF] == v->window)
    {
        write_buf(v->output, &v->output_offset, &v->decoded[v->dict_size], 0xFFFF - v->dict_size);
        memmove(v->decoded, &v->window[-v->dict_size], v->dict_size);
        v->window = &v->decoded[v->dict_size];
    }

    *v->window++ = b;
    v->unpacked_crc_real = crc_table[(v->unpacked_crc_real ^ b) & 0xFF] ^ v->unpacked_crc_real >> 8;
}

int unpack_data_m2(vars_t* v)
{
    while (v->processed_size < v->input_size)
    {
        while (1)
        {
            if (!input_bits_m2(v, 1))
            {
                write_decoded_byte(v, (v->enc_key ^ read_source_byte(v)) & 0xFF);

                ror_w(&v->enc_key);

                v->processed_size++;
            }
            else
            {
                if (input_bits_m2(v, 1))
                {
                    if (input_bits_m2(v, 1))
                    {
                        if (input_bits_m2(v, 1))
                        {
                            v->match_count = read_source_byte(v) + 8;

                            if (v->match_count == 8)
                            {
                                input_bits_m2(v, 1);
                                break;
                            }
                        }
                        else
                        {
                            v->match_count = 3;
                        }

                        decode_match_offset(v);
                    }
                    else
                    {
                        v->match_count = 2;
                        v->match_offset = read_source_byte(v) + 1;
                    }

                    v->processed_size += v->match_count;

                    while (v->match_count--)
                        write_decoded_byte(v, v->window[-v->match_offset]);
                }
                else
                {
                    decode_match_count(v);

                    if (v->match_count != 9)
                    {
                        decode_match_offset(v);
                        v->processed_size += v->match_count;

                        while (v->match_count--)
                            write_decoded_byte(v, v->window[-v->match_offset]);
                    }
                    else
                    {
                        uint32 data_length = (input_bits_m2(v, 4) << 2) + 12;
                        v->processed_size += data_length;

                        while (data_length--)
                            write_decoded_byte(v, (v->enc_key ^ read_source_byte(v)) & 0xFF);

                        ror_w(&v->enc_key);
                    }
                }
            }
        }
    }

    write_buf(v->output, &v->output_offset, &v->decoded[v->dict_size], v->window - &v->decoded[v->dict_size]);
    return 0;
}

enum error_codes do_unpack_data(vars_t* v)
{
    const int start_pos = v->input_offset;

    const uint32 sign = read_dword_be(v->input, &v->input_offset);
    if (sign >> 8 != RNC_SIGN)
        return error_wrong_rnc_header;

    v->method = sign & 3;
    v->input_size = read_dword_be(v->input, &v->input_offset);
    v->packed_size = read_dword_be(v->input, &v->input_offset);
    if (v->file_size < v->packed_size)
        return error_wrong_rnc_header_2;
    v->unpacked_crc = read_word_be(v->input, &v->input_offset);
    v->packed_crc = read_word_be(v->input, &v->input_offset);

    /*v->leeway = */ read_byte(v->input, &v->input_offset);
    /*v->chunks_count = */ read_byte(v->input, &v->input_offset);

    if (crc_block(v->input, v->input_offset, v->packed_size) != v->packed_crc)
        return error_corrupted_input_data;

    v->mem1 = (uint8*)malloc(0xFFFF);
    v->decoded = (uint8*)malloc(0xFFFF);
    v->pack_block_start = &v->mem1[0xFFFD];
    v->window = &v->decoded[v->dict_size];

    v->unpacked_crc_real = 0;
    v->bit_count = 0;
    v->bit_buffer = 0;
    v->processed_size = 0;

    const uint16 specified_key = v->enc_key;

    enum error_codes error_code = 0;
    input_bits_m2(v, 1);

    if (!error_code)
    {
        if (input_bits_m2(v, 1) && !v->enc_key) // key is needed, but not specified as argument
            error_code = error_decryption_key_required;
    }

    if (!error_code)
    {
        switch (v->method)
        {
        case 2: error_code = unpack_data_m2(v); break;
        }
    }

    v->enc_key = specified_key;

    free(v->mem1);
    free(v->decoded);

    v->input_offset = start_pos + v->packed_size + RNC_HEADER_SIZE;

    if (error_code)
        return error_code;

    if (v->unpacked_crc != v->unpacked_crc_real)
        return error_crc_check_failed;

    return error_none;
}

enum error_codes do_unpack(vars_t* v)
{
    v->packed_size = v->file_size;

    if (v->file_size < RNC_HEADER_SIZE)
        return 6;

    return do_unpack_data(v);
}

int main(int argc, char* argv[])
{
    argv[1] = "u";
    argv[2] = "E:\\repos-external\\rnc_propack_source\\CRATES.GSC";
    argv[3] = "E:\\repos-external\\rnc_propack_source\\CRATES_C.NUS";

    vars_t* v = init_vars();
    FILE* in = fopen(argv[2], "rb");
    if (in == NULL)
    {
        free(v);
        printf("Cannot open input file!\n");
        return -1;
    }
    fseek(in, 0, SEEK_END);
    v->file_size = ftell(in) - v->read_start_offset;
    fseek(in, v->read_start_offset, SEEK_SET);
    v->input = (uint8*)malloc(v->file_size);
    fread(v->input, v->file_size, 1, in);
    fclose(in);

    v->output = (uint8*)malloc(MAX_BUF_SIZE);

    const enum error_codes error_code = do_unpack(v);
    if (!error_code)
    {
        FILE* out = fopen(argv[3], "wb");
        if (out == NULL)
        {
            free(v->input);
            free(v->output);
            free(v);
            printf("Cannot create output file!\n");
            return -1;
        }

        fwrite(v->output, v->output_offset, 1, out);
        fclose(out);

        printf("File successfully %s!\n", "unpacked");
        printf("Original/new size: %d/%zd bytes\n",
               v->packed_size + RNC_HEADER_SIZE, v->output_offset);
    }
    else
    {
        switch (error_code)
        {
        case error_corrupted_input_data: printf("Corrupted input data.\n");
            break;
        case error_crc_check_failed: printf("CRC check failed.\n");
            break;
        case error_wrong_rnc_header:
        case error_wrong_rnc_header_2: printf("Wrong RNC header.\n");
            break;
        case error_decryption_key_required: printf("Decryption key required.\n");
            break;
        case error_no_rnc_archives_were_found: printf("No RNC archives were found.\n");
            break;
        default: printf("Cannot process file. Error code: %x\n", error_code);
            break;
        }
    }

    free(v->input);
    free(v->output);
    free(v);

    return error_code;
}
