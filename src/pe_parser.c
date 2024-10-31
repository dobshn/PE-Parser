#include <stdio.h>
#include <stdint.h>
#include <time.h>

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

void printOptionalHeader(const IMAGE_OPTIONAL_HEADER32 *optionalHeader) {
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
