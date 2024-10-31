#include <stdio.h>
#include <stdint.h>

typedef struct _IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t e_lfanew;
} IMAGE_DOS_HEADER;

// PE 헤더 구조체 정의
typedef struct {
    uint16_t VirtualAddress;
    uint16_t Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

int main() {
    FILE *peFile = fopen("sample.exe", "rb");
    if (peFile == NULL) {
        printf("파일을 열 수 없습니다.\n");
        return 1;
    }

    IMAGE_DOS_HEADER dosHeader;
    fread(&dosHeader, sizeof(dosHeader), 1, peFile);

    if (dosHeader.e_magic != 0x5A4D) {
        printf("PE 파일이 아닙니다.\n");
        return 1;
    }

    // DOS 헤더 정보 출력
    printf("*******************\n");
    printf("* DOS Header의 정보 *\n");
    printf("*******************\n");
    printf("e_magic      : 0x%X\n", dosHeader.e_magic);
    printf("e_cblp       : %u\n", dosHeader.e_cblp);
    printf("e_cp         : %u\n", dosHeader.e_cp);
    printf("e_crlc       : %u\n", dosHeader.e_crlc);
    printf("e_cparhdr    : %u\n", dosHeader.e_cparhdr);
    printf("e_minalloc   : %u\n", dosHeader.e_minalloc);
    printf("e_maxalloc   : %u\n", dosHeader.e_maxalloc);
    printf("e_ss         : 0x%X\n", dosHeader.e_ss);
    printf("e_sp         : 0x%X\n", dosHeader.e_sp);
    printf("e_csum       : 0x%X\n", dosHeader.e_csum);
    printf("e_ip         : 0x%X\n", dosHeader.e_ip);
    printf("e_cs         : 0x%X\n", dosHeader.e_cs);
    printf("e_lfarlc     : 0x%X\n", dosHeader.e_lfarlc);
    printf("e_ovno       : %u\n", dosHeader.e_ovno);
    printf("e_res        : {0x%X, 0x%X, 0x%X, 0x%X}\n",
           dosHeader.e_res[0], dosHeader.e_res[1],
           dosHeader.e_res[2], dosHeader.e_res[3]);
    printf("e_oemid      : 0x%X\n", dosHeader.e_oemid);
    printf("e_oeminfo    : 0x%X\n", dosHeader.e_oeminfo);
    printf("e_res2       : {0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X}\n",
           dosHeader.e_res2[0], dosHeader.e_res2[1],
           dosHeader.e_res2[2], dosHeader.e_res2[3],
           dosHeader.e_res2[4], dosHeader.e_res2[5],
           dosHeader.e_res2[6], dosHeader.e_res2[7],
           dosHeader.e_res2[8], dosHeader.e_res2[9]);
    printf("e_lfanew     : 0x%X\n", dosHeader.e_lfanew);

    // DOS 스텁 정보 출력(크기)
    printf("\n*******************\n");
    printf("*  DOS Stub의 정보  *\n");
    printf("*******************\n");
    printf("DOS Stub의 크기: %lu 바이트\n", dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER));

    return 0;
}
