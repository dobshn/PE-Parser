#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

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
    uint32_t VirtualAddress;
    uint32_t Size;
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
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
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
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

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

typedef struct {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    uint8_t  Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

const char* getMachine(uint16_t machine) {
    switch (machine) {
        case 0x014c: return "x86";
        case 0x0200: return "Intel Itanium";
        case 0x8664: return "x64";
        default: return "Unknown Machine Type";
    }
}

void printTimeDateStamp(uint32_t timestamp) {
    // 타임스탬프를 time_t로 변환
    time_t rawtime = (time_t)timestamp;

    // 타임스탬프를 현지 시간 구조체로 변환
    struct tm *timeinfo = localtime(&rawtime);
    if (timeinfo != NULL) {
        // 날짜와 시간을 원하는 형식으로 출력
        char buffer[64];
        strftime(buffer, sizeof(buffer), "%Y년 %m월 %d일 %H시 %M분 %S초", timeinfo);
        printf("TimeDateStamp           : %s\n", buffer);
    } else {
        printf("TimeDateStamp           : 변환 실패\n");
    }
}

void printCharacteristics(uint16_t characteristics) {
    printf("Characteristics         :\n");
    if (characteristics & 0x0001) printf(" - 재배치 정보가 파일에서 제거되었습니다.\n");
    if (characteristics & 0x0002) printf(" - 파일은 실행 가능 상태입니다.\n");
    if (characteristics & 0x0004) printf(" - COFF 라인 번호가 파일에서 제거되었습니다.\n");
    if (characteristics & 0x0008) printf(" - COFF 심볼 테이블 항목이 파일에서 제거되었습니다.\n");
    if (characteristics & 0x0010) printf(" - 작업 집합을 적극적으로 줄입니다 (사용되지 않음).\n");
    if (characteristics & 0x0020) printf(" - 애플리케이션이 2GB 이상의 주소를 처리할 수 있습니다.\n");
    if (characteristics & 0x0080) printf(" - 워드의 바이트 순서가 반대로 저장됩니다 (사용되지 않음).\n");
    if (characteristics & 0x0100) printf(" - 컴퓨터가 32비트 워드를 지원합니다.\n");
    if (characteristics & 0x0200) printf(" - 디버깅 정보가 제거되었고 별도의 파일에 저장되었습니다.\n");
    if (characteristics & 0x0400) printf(" - 이미지가 이동식 미디어에 있을 경우, 스왑 파일에 복사하여 실행합니다.\n");
    if (characteristics & 0x0800) printf(" - 이미지가 네트워크에 있을 경우, 스왑 파일에 복사하여 실행합니다.\n");
    if (characteristics & 0x1000) printf(" - 이 이미지는 시스템 파일입니다.\n");
    if (characteristics & 0x2000) printf(" - 이 이미지는 DLL 파일입니다.\n");
    if (characteristics & 0x4000) printf(" - 파일은 단일 프로세서 컴퓨터에서만 실행해야 합니다.\n");
    if (characteristics & 0x8000) printf(" - 워드의 바이트 순서가 반대로 저장됩니다.\n");
}

void printFileHeader(const IMAGE_FILE_HEADER *fileHeader) {
    printf("*******************\n");
    printf("* File Header 정보 *\n");
    printf("*******************\n");
    printf("Machine                 : %s\n", getMachine(fileHeader->Machine));
    printf("NumberOfSections        : %u개\n", fileHeader->NumberOfSections);
    printTimeDateStamp(fileHeader->TimeDateStamp);
    printf("PointerToSymbolTable    : 0x%X\n", fileHeader->PointerToSymbolTable);
    printf("NumberOfSymbols         : %u개\n", fileHeader->NumberOfSymbols);
    printf("SizeOfOptionalHeader    : %u 바이트\n", fileHeader->SizeOfOptionalHeader);
    printCharacteristics(fileHeader->Characteristics);
}

const char* getMagic(uint16_t magic) {
    switch (magic) {
        case 0x010B: return "PE32 (32비트)";
        case 0x020B: return "PE32+ (64비트)";
        case 0x0107: return "ROM 이미지";
        default: return "알 수 없는 매직 넘버";
    }
}

const char* getSubsystem(uint16_t subsystem) {
    switch (subsystem) {
        case 0:  return "알 수 없음";
        case 1:  return "네이티브";
        case 2:  return "Windows GUI";
        case 3:  return "Windows CUI";
        case 5:  return "OS/2 CUI";
        case 7:  return "POSIX CUI";
        case 9:  return "Windows CE GUI";
        case 10: return "EFI 응용 프로그램";
        case 11: return "EFI 부트 서비스 드라이버";
        case 12: return "EFI 런타임 드라이버";
        case 13: return "EFI ROM";
        case 14: return "XBOX";
        case 16: return "Windows 부트 애플리케이션";
        default: return "알 수 없는 서브시스템";
    }
}

void printDllCharacteristics(uint16_t dllCharacteristics) {
    printf("DllCharacteristics      :\n");
    if (dllCharacteristics & 0x0040) printf(" - 주소 공간 배치 랜덤화 사용 가능 (ASLR)\n");
    if (dllCharacteristics & 0x0080) printf(" - 무결성 체크 필요\n");
    if (dllCharacteristics & 0x0100) printf(" - DEP 사용 가능\n");
    if (dllCharacteristics & 0x0200) printf(" - Isolation 사용 안 함\n");
    if (dllCharacteristics & 0x0400) printf(" - SEH 사용 안 함\n");
    if (dllCharacteristics & 0x0800) printf(" - 바인딩 사용 안 함\n");
    if (dllCharacteristics & 0x1000) printf(" - AppContainer에서 실행\n");
    if (dllCharacteristics & 0x2000) printf(" - WDM 드라이버\n");
    if (dllCharacteristics & 0x8000) printf(" - 터미널 서버 인식\n");
}

void printDataDirectories(const IMAGE_DATA_DIRECTORY* dataDirectories, uint32_t numberOfRvaAndSizes) {
    const char* directoryNames[] = {
        "Export Table",
        "Import Table",
        "Resource Table",
        "Exception Table",
        "Certificate Table",
        "Base Relocation Table",
        "Debug",
        "Architecture",
        "Global Ptr",
        "TLS Table",
        "Load Config Table",
        "Bound Import",
        "IAT",
        "Delay Import Descriptor",
        "CLR Runtime Header",
        "Reserved"
    };

    printf("Data Directories:\n");
    for (uint32_t i = 0; i < numberOfRvaAndSizes && i < 16; ++i) {
        printf(" [%u] %s\n", i, directoryNames[i]);
        printf("     VirtualAddress: 0x%X\n", dataDirectories[i].VirtualAddress);
        printf("     Size          : 0x%X\n", dataDirectories[i].Size);
    }
}

void printDosHeader(const IMAGE_DOS_HEADER *dosHeader) {
    printf("*******************\n");
    printf("* DOS Header의 정보 *\n");
    printf("*******************\n");
    printf("e_magic      : 0x%X\n", dosHeader->e_magic);
    printf("e_cblp       : %u\n", dosHeader->e_cblp);
    printf("e_cp         : %u\n", dosHeader->e_cp);
    printf("e_crlc       : %u\n", dosHeader->e_crlc);
    printf("e_cparhdr    : %u\n", dosHeader->e_cparhdr);
    printf("e_minalloc   : %u\n", dosHeader->e_minalloc);
    printf("e_maxalloc   : %u\n", dosHeader->e_maxalloc);
    printf("e_ss         : 0x%X\n", dosHeader->e_ss);
    printf("e_sp         : 0x%X\n", dosHeader->e_sp);
    printf("e_csum       : 0x%X\n", dosHeader->e_csum);
    printf("e_ip         : 0x%X\n", dosHeader->e_ip);
    printf("e_cs         : 0x%X\n", dosHeader->e_cs);
    printf("e_lfarlc     : 0x%X\n", dosHeader->e_lfarlc);
    printf("e_ovno       : %u\n", dosHeader->e_ovno);
    printf("e_res        : {0x%X, 0x%X, 0x%X, 0x%X}\n",
           dosHeader->e_res[0], dosHeader->e_res[1],
           dosHeader->e_res[2], dosHeader->e_res[3]);
    printf("e_oemid      : 0x%X\n", dosHeader->e_oemid);
    printf("e_oeminfo    : 0x%X\n", dosHeader->e_oeminfo);
    printf("e_res2       : {0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X}\n",
           dosHeader->e_res2[0], dosHeader->e_res2[1],
           dosHeader->e_res2[2], dosHeader->e_res2[3],
           dosHeader->e_res2[4], dosHeader->e_res2[5],
           dosHeader->e_res2[6], dosHeader->e_res2[7],
           dosHeader->e_res2[8], dosHeader->e_res2[9]);
    printf("e_lfanew     : 0x%X\n", dosHeader->e_lfanew);

    // DOS 스텁 정보 출력(크기)
    printf("\n*******************\n");
    printf("*  DOS Stub의 정보  *\n");
    printf("*******************\n");
    printf("DOS Stub의 크기: %lu 바이트\n", dosHeader->e_lfanew - sizeof(IMAGE_DOS_HEADER));
}

void printOptionalHeader32(const IMAGE_OPTIONAL_HEADER32 *optionalHeader) {
    printf("***********************\n");
    printf("* Optional Header 정보 *\n");
    printf("***********************\n");
    printf("Magic                   : %s\n", getMagic(optionalHeader->Magic));
    printf("MajorLinkerVersion      : %u\n", optionalHeader->MajorLinkerVersion);
    printf("MinorLinkerVersion      : %u\n", optionalHeader->MinorLinkerVersion);
    printf("SizeOfCode              : 0x%X\n", optionalHeader->SizeOfCode);
    printf("SizeOfInitializedData   : 0x%X\n", optionalHeader->SizeOfInitializedData);
    printf("SizeOfUninitializedData : 0x%X\n", optionalHeader->SizeOfUninitializedData);
    printf("AddressOfEntryPoint     : 0x%X\n", optionalHeader->AddressOfEntryPoint);
    printf("BaseOfCode              : 0x%X\n", optionalHeader->BaseOfCode);
    printf("BaseOfData              : 0x%X\n", optionalHeader->BaseOfData);
    printf("ImageBase               : 0x%X\n", optionalHeader->ImageBase);
    printf("SectionAlignment        : 0x%X\n", optionalHeader->SectionAlignment);
    printf("FileAlignment           : 0x%X\n", optionalHeader->FileAlignment);
    printf("MajorOperatingSystemVersion: %u\n", optionalHeader->MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: %u\n", optionalHeader->MinorOperatingSystemVersion);
    printf("MajorImageVersion       : %u\n", optionalHeader->MajorImageVersion);
    printf("MinorImageVersion       : %u\n", optionalHeader->MinorImageVersion);
    printf("MajorSubsystemVersion   : %u\n", optionalHeader->MajorSubsystemVersion);
    printf("MinorSubsystemVersion   : %u\n", optionalHeader->MinorSubsystemVersion);
    printf("Win32VersionValue       : %u\n", optionalHeader->Win32VersionValue);
    printf("SizeOfImage             : 0x%X\n", optionalHeader->SizeOfImage);
    printf("SizeOfHeaders           : 0x%X\n", optionalHeader->SizeOfHeaders);
    printf("CheckSum                : 0x%X\n", optionalHeader->CheckSum);
    printf("Subsystem               : %s\n", getSubsystem(optionalHeader->Subsystem));
    printDllCharacteristics(optionalHeader->DllCharacteristics);
    printf("SizeOfStackReserve      : 0x%X\n", optionalHeader->SizeOfStackReserve);
    printf("SizeOfStackCommit       : 0x%X\n", optionalHeader->SizeOfStackCommit);
    printf("SizeOfHeapReserve       : 0x%X\n", optionalHeader->SizeOfHeapReserve);
    printf("SizeOfHeapCommit        : 0x%X\n", optionalHeader->SizeOfHeapCommit);
    printf("LoaderFlags             : 0x%X\n", optionalHeader->LoaderFlags);
    printf("NumberOfRvaAndSizes     : %u\n", optionalHeader->NumberOfRvaAndSizes);
    printDataDirectories(optionalHeader->DataDirectory, optionalHeader->NumberOfRvaAndSizes);
}

void printOptionalHeader64(const IMAGE_OPTIONAL_HEADER64 *optionalHeader) {
    printf("***********************\n");
    printf("* Optional Header 정보 (64비트) *\n");
    printf("***********************\n");
    printf("Magic                   : %s\n", getMagic(optionalHeader->Magic));
    printf("MajorLinkerVersion      : %u\n", optionalHeader->MajorLinkerVersion);
    printf("MinorLinkerVersion      : %u\n", optionalHeader->MinorLinkerVersion);
    printf("SizeOfCode              : 0x%X\n", optionalHeader->SizeOfCode);
    printf("SizeOfInitializedData   : 0x%X\n", optionalHeader->SizeOfInitializedData);
    printf("SizeOfUninitializedData : 0x%X\n", optionalHeader->SizeOfUninitializedData);
    printf("AddressOfEntryPoint     : 0x%X\n", optionalHeader->AddressOfEntryPoint);
    printf("BaseOfCode              : 0x%X\n", optionalHeader->BaseOfCode);
    printf("ImageBase               : 0x%llX\n", (unsigned long long)optionalHeader->ImageBase);
    printf("SectionAlignment        : 0x%X\n", optionalHeader->SectionAlignment);
    printf("FileAlignment           : 0x%X\n", optionalHeader->FileAlignment);
    printf("MajorOperatingSystemVersion: %u\n", optionalHeader->MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: %u\n", optionalHeader->MinorOperatingSystemVersion);
    printf("MajorImageVersion       : %u\n", optionalHeader->MajorImageVersion);
    printf("MinorImageVersion       : %u\n", optionalHeader->MinorImageVersion);
    printf("MajorSubsystemVersion   : %u\n", optionalHeader->MajorSubsystemVersion);
    printf("MinorSubsystemVersion   : %u\n", optionalHeader->MinorSubsystemVersion);
    printf("Win32VersionValue       : %u\n", optionalHeader->Win32VersionValue);
    printf("SizeOfImage             : 0x%X\n", optionalHeader->SizeOfImage);
    printf("SizeOfHeaders           : 0x%X\n", optionalHeader->SizeOfHeaders);
    printf("CheckSum                : 0x%X\n", optionalHeader->CheckSum);
    printf("Subsystem               : %s\n", getSubsystem(optionalHeader->Subsystem));
    printDllCharacteristics(optionalHeader->DllCharacteristics);
    printf("SizeOfStackReserve      : 0x%llX\n", (unsigned long long)optionalHeader->SizeOfStackReserve);
    printf("SizeOfStackCommit       : 0x%llX\n", (unsigned long long)optionalHeader->SizeOfStackCommit);
    printf("SizeOfHeapReserve       : 0x%llX\n", (unsigned long long)optionalHeader->SizeOfHeapReserve);
    printf("SizeOfHeapCommit        : 0x%llX\n", (unsigned long long)optionalHeader->SizeOfHeapCommit);
    printf("LoaderFlags             : 0x%X\n", optionalHeader->LoaderFlags);
    printf("NumberOfRvaAndSizes     : %u\n", optionalHeader->NumberOfRvaAndSizes);
    printDataDirectories(optionalHeader->DataDirectory, optionalHeader->NumberOfRvaAndSizes);
}

void printNtHeader32(const IMAGE_NT_HEADERS32 *ntHeader) {
    printf("*******************\n");
    printf("* NT Header 정보 *\n");
    printf("*******************\n");
    printf("Signature               : 0x%X\n", ntHeader->Signature);

    printFileHeader(&ntHeader->FileHeader);

    printOptionalHeader32(&ntHeader->OptionalHeader);
}

void printNtHeader64(const IMAGE_NT_HEADERS64 *ntHeader) {
    printf("*******************\n");
    printf("* NT Header 정보 *\n");
    printf("*******************\n");
    printf("Signature               : 0x%X\n", ntHeader->Signature);

    printFileHeader(&ntHeader->FileHeader);

    printOptionalHeader64(&ntHeader->OptionalHeader);
}

void printSectionCharacteristics(const uint32_t characteristics) {
    printf("Characteristics         : 0x%X\n", characteristics);

    if (characteristics & 0x00000001) printf("0x00000001 - 예약되어 있습니다.\n");
    if (characteristics & 0x00000002) printf("0x00000002 - 예약되어 있습니다.\n");
    if (characteristics & 0x00000004) printf("0x00000004 - 예약되어 있습니다.\n");
    if (characteristics & 0x00000008) printf("IMAGE_SCN_TYPE_NO_PAD\n0x00000008 - 섹션을 다음 경계까지 채우지 않습니다. 이 플래그는 더 이상 사용되지 않으며 IMAGE_SCN_ALIGN_1BYTES로 대체됩니다.\n");
    if (characteristics & 0x00000010) printf("0x00000010 - 예약되어 있습니다.\n");
    if (characteristics & 0x00000020) printf("IMAGE_SCN_CNT_CODE\n0x00000020 - 실행 코드가 섹션에 포함됩니다.\n");
    if (characteristics & 0x00000040) printf("IMAGE_SCN_CNT_INITIALIZED_DATA\n0x00000040 - 초기화된 데이터가 섹션에 포함됩니다.\n");
    if (characteristics & 0x00000080) printf("IMAGE_SCN_CNT_UNINITIALIZED_DATA\n0x00000080 - 초기화되지 않은 데이터가 섹션에 포함됩니다.\n");
    if (characteristics & 0x00000100) printf("IMAGE_SCN_LNK_OTHER\n0x00000100 - 예약되어 있습니다.\n");
    if (characteristics & 0x00000200) printf("IMAGE_SCN_LNK_INFO\n0x00000200 - 주석 또는 기타 정보가 섹션에 포함됩니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00000800) printf("IMAGE_SCN_LNK_REMOVE\n0x00000800 - 섹션이 이미지의 일부가 되지 않습니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00001000) printf("IMAGE_SCN_LNK_COMDAT\n0x00001000 - COMDAT 데이터가 섹션에 포함됩니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00004000) printf("IMAGE_SCN_NO_DEFER_SPEC_EXC\n0x00004000 - 이 섹션의 TLB 항목에서 비트를 처리하는 투기적 예외를 다시 설정합니다.\n");
    if (characteristics & 0x00008000) printf("IMAGE_SCN_GPREL\n0x00008000 - 섹션에는 전역 포인터를 통해 참조되는 데이터가 포함되어 있습니다.\n");

    // 예약된 값들
    if (characteristics & 0x00010000) printf("0x00010000 - 예약되어 있습니다.\n");
    if (characteristics & 0x00020000) printf("IMAGE_SCN_MEM_PURGEABLE\n0x00020000 - 예약되어 있습니다.\n");
    if (characteristics & 0x00040000) printf("IMAGE_SCN_MEM_LOCKED\n0x00040000 - 예약되어 있습니다.\n");
    if (characteristics & 0x00080000) printf("IMAGE_SCN_MEM_PRELOAD\n0x00080000 - 예약되어 있습니다.\n");

    // Alignment 값들
    if (characteristics & 0x00100000) printf("IMAGE_SCN_ALIGN_1BYTES\n0x00100000 - 데이터를 1바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00200000) printf("IMAGE_SCN_ALIGN_2BYTES\n0x00200000 - 데이터를 2바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00300000) printf("IMAGE_SCN_ALIGN_4BYTES\n0x00300000 - 데이터를 4바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00400000) printf("IMAGE_SCN_ALIGN_8BYTES\n0x00400000 - 데이터를 8바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00500000) printf("IMAGE_SCN_ALIGN_16BYTES\n0x00500000 - 데이터를 16바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00600000) printf("IMAGE_SCN_ALIGN_32BYTES\n0x00600000 - 데이터를 32바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00700000) printf("IMAGE_SCN_ALIGN_64BYTES\n0x00700000 - 데이터를 64바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00800000) printf("IMAGE_SCN_ALIGN_128BYTES\n0x00800000 - 데이터를 128바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00900000) printf("IMAGE_SCN_ALIGN_256BYTES\n0x00900000 - 데이터를 256바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00A00000) printf("IMAGE_SCN_ALIGN_512BYTES\n0x00A00000 - 데이터를 512바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00B00000) printf("IMAGE_SCN_ALIGN_1024BYTES\n0x00B00000 - 데이터를 1,024바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00C00000) printf("IMAGE_SCN_ALIGN_2048BYTES\n0x00C00000 - 데이터를 2,048바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00D00000) printf("IMAGE_SCN_ALIGN_4096BYTES\n0x00D00000 - 데이터를 4,096바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");
    if (characteristics & 0x00E00000) printf("IMAGE_SCN_ALIGN_8192BYTES\n0x00E00000 - 데이터를 8,192바이트 경계에 맞춥니다. 개체 파일에만 유효합니다.\n");

    // 기타 속성들
    if (characteristics & 0x01000000) printf("IMAGE_SCN_LNK_NRELOC_OVFL\n0x01000000 - 확장 재배치가 섹션에 포함됩니다.\n");
    if (characteristics & 0x02000000) printf("IMAGE_SCN_MEM_DISCARDABLE\n0x02000000 - 필요에 따라 섹션을 삭제할 수 있습니다.\n");
    if (characteristics & 0x04000000) printf("IMAGE_SCN_MEM_NOT_CACHED\n0x04000000 - 섹션을 캐시할 수 없습니다.\n");
    if (characteristics & 0x08000000) printf("IMAGE_SCN_MEM_NOT_PAGED\n0x08000000 - 섹션을 페이징할 수 없습니다.\n");
    if (characteristics & 0x10000000) printf("IMAGE_SCN_MEM_SHARED\n0x10000000 - 메모리에서 섹션을 공유할 수 있습니다.\n");
    if (characteristics & 0x20000000) printf("IMAGE_SCN_MEM_EXECUTE\n0x20000000 - 섹션을 코드로 실행할 수 있습니다.\n");
    if (characteristics & 0x40000000) printf("IMAGE_SCN_MEM_READ\n0x40000000 - 섹션을 읽을 수 있습니다.\n");
    if (characteristics & 0x80000000) printf("IMAGE_SCN_MEM_WRITE\n0x80000000 - 섹션에 쓸 수 있습니다.\n");
}

void printSectionHeader(const IMAGE_SECTION_HEADER* sectionHeader) {
    printf("\n*******************\n");
    printf("* 섹션 헤더 정보  *\n");
    printf("*******************\n");
    printf("섹션 이름              : %.8s\n", sectionHeader->Name);
    printf("메모리에서의 크기      : %u\n", sectionHeader->Misc.VirtualSize);
    printf("메모리 시작 주소       : 0x%X\n", sectionHeader->VirtualAddress);
    printf("파일에서의 크기        : %u\n", sectionHeader->SizeOfRawData);
    printf("파일에서의 위치        : 0x%X\n", sectionHeader->PointerToRawData);
    printf("재배치 정보 위치       : 0x%X\n", sectionHeader->PointerToRelocations);
    printf("줄 번호 정보 위치      : 0x%X\n", sectionHeader->PointerToLinenumbers);
    printf("재배치 수              : %u\n", sectionHeader->NumberOfRelocations);
    printf("줄 번호 수             : %u\n", sectionHeader->NumberOfLinenumbers);
    printSectionCharacteristics(sectionHeader->Characteristics);
}

int main() {
    char filename[256];

    while (1) {
        printf("\n===== PE Parser =====\n");
        printf("분석할 파일명을 입력하세요 (q 입력시 종료): ");

        // fgets를 사용하여 입력 받기
        if (fgets(filename, sizeof(filename), stdin) == NULL) {
            continue; // 다시 루프로
        }

        // 개행문자 제거
        size_t len = strlen(filename);
        if (len > 0 && filename[len-1] == '\n') {
            filename[len-1] = '\0';
        }

        // q 입력 시 종료
        if (strcmp(filename, "q") == 0) {
            printf("프로그램을 종료합니다.\n");
            break;
        }

        FILE *peFile = fopen(filename, "rb");
        if (peFile == NULL) {
            printf("파일을 열 수 없습니다: %s\n", filename);
            continue; // 시작화면으로 돌아가기
        }

        IMAGE_DOS_HEADER dosHeader;
        if (fread(&dosHeader, sizeof(dosHeader), 1, peFile) != 1 || dosHeader.e_magic != 0x5A4D) {
            printf("PE 파일이 아니거나 읽기 실패.\n");
            fclose(peFile);
            continue;
        }

        IMAGE_NT_HEADERS32 ntHeaders32;
        fseek(peFile, dosHeader.e_lfanew, SEEK_SET);
        if (fread(&ntHeaders32, sizeof(IMAGE_NT_HEADERS32), 1, peFile) != 1 || ntHeaders32.Signature != 0x00004550) {
            printf("올바르지 않은 NT Header Signature입니다.\n");
            fclose(peFile);
            continue;
        }

        // 분석 시작
        printDosHeader(&dosHeader);
        printNtHeader32(&ntHeaders32);

        for (int i = 0; i < ntHeaders32.FileHeader.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER sectionHeader;
            if (fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, peFile) != 1) {
                printf("섹션 헤더 읽기 실패.\n");
                break;
            }
            printSectionHeader(&sectionHeader);
            printf("\n");
        }

        fclose(peFile);
        // 분석 끝난 후에도 다시 시작화면으로 돌아감
    }

    return 0;
}
