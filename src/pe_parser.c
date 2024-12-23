#include <stdio.h>
#include <stdint.h>

// DOS_HEADER 구조체 정의
typedef struct {
    uint16_t e_magic;      // Magic number (DOS 헤더의 시그니처, "MZ")
    uint16_t e_cblp;       // 파일의 마지막 페이지의 바이트 수
    uint16_t e_cp;         // 파일 페이지 수
    uint16_t e_crlc;       // 재배치 수
    uint16_t e_cparhdr;    // 헤더 크기 (단위: Paragraph)
    uint16_t e_minalloc;   // 필요한 최소 추가 메모리 (단위: Paragraph)
    uint16_t e_maxalloc;   // 최대 추가 메모리 (단위: Paragraph)
    uint16_t e_ss;         // 초기 SS 레지스터 값
    uint16_t e_sp;         // 초기 SP 레지스터 값
    uint16_t e_csum;       // 체크섬
    uint16_t e_ip;         // 초기 IP 값
    uint16_t e_cs;         // 초기 CS 값
    uint16_t e_lfarlc;     // 재배치 테이블 파일 오프셋
    uint16_t e_ovno;       // 오버레이 번호
    uint16_t e_res[4];     // 예약된 공간
    uint16_t e_oemid;      // OEM ID
    uint16_t e_oeminfo;    // OEM 정보
    uint16_t e_res2[10];   // 추가 예약 공간
    int32_t e_lfanew;      // PE 헤더의 파일 오프셋
} IMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    uint16_t Machine;              // 대상 머신 아키텍처 (예: x86, x64)
    uint16_t NumberOfSections;     // 섹션의 개수
    uint32_t TimeDateStamp;        // 파일 생성 시간 (Unix 시간 기준)
    uint32_t PointerToSymbolTable; // 심볼 테이블의 파일 오프셋 (일반적으로 0)
    uint32_t NumberOfSymbols;      // 심볼의 개수 (일반적으로 0)
    uint16_t SizeOfOptionalHeader; // Optional Header의 크기 (바이트)
    uint16_t Characteristics;      // 파일 속성 (실행 가능, DLL 여부 등)
} IMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;  // 데이터 디렉터리가 메모리에 로드될 가상 주소
    uint32_t Size;            // 데이터 디렉터리의 크기
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;                     // PE32는 0x10B
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;                // 32비트에서만 존재
    uint32_t ImageBase;                 // 32비트에서 4바이트
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

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;                     // PE32+는 0x20B
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;                 // 64비트에서 8바이트
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
    uint64_t SizeOfStackReserve;        // 64비트에서 8바이트
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS32 {
    uint32_t Signature;               // PE Signature ("PE\0\0")
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
    uint32_t Signature;               // PE Signature ("PE\0\0")
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    uint8_t  Name[8];               // 섹션 이름
    uint32_t VirtualSize;           // 메모리에서의 크기
    uint32_t VirtualAddress;        // 메모리에서의 시작 주소
    uint32_t SizeOfRawData;         // 파일에서의 크기
    uint32_t PointerToRawData;      // 파일에서의 위치
    uint32_t PointerToRelocations;  // 재배치 정보의 위치
    uint32_t PointerToLinenumbers;  // 줄 번호 정보의 위치
    uint16_t NumberOfRelocations;   // 재배치 수
    uint16_t NumberOfLinenumbers;   // 줄 번호 수
    uint32_t Characteristics;       // 속성 (코드, 데이터, 실행 가능 등)
} IMAGE_SECTION_HEADER;

void printOptionalHeader32(IMAGE_OPTIONAL_HEADER32 optionalHeader) {
    printf("\n***********************\n");
    printf("* Optional Header 정보 (32비트) *\n");
    printf("***********************\n");
    printf("Magic                     : 0x%X\n", optionalHeader.Magic);
    printf("Major Linker Version      : %u\n", optionalHeader.MajorLinkerVersion);
    printf("Minor Linker Version      : %u\n", optionalHeader.MinorLinkerVersion);
    printf("Size of Code              : %u\n", optionalHeader.SizeOfCode);
    printf("Size of Initialized Data  : %u\n", optionalHeader.SizeOfInitializedData);
    printf("Size of Uninitialized Data: %u\n", optionalHeader.SizeOfUninitializedData);
    printf("Address of Entry Point    : 0x%X\n", optionalHeader.AddressOfEntryPoint);
    printf("Base of Code              : 0x%X\n", optionalHeader.BaseOfCode);
    printf("Base of Data              : 0x%X\n", optionalHeader.BaseOfData);
    printf("Image Base                : 0x%X\n", optionalHeader.ImageBase);
    printf("Section Alignment         : %u\n", optionalHeader.SectionAlignment);
    printf("File Alignment            : %u\n", optionalHeader.FileAlignment);
    printf("Major Operating System Version : %u\n", optionalHeader.MajorOperatingSystemVersion);
    printf("Minor Operating System Version : %u\n", optionalHeader.MinorOperatingSystemVersion);
    printf("Major Image Version       : %u\n", optionalHeader.MajorImageVersion);
    printf("Minor Image Version       : %u\n", optionalHeader.MinorImageVersion);
    printf("Major Subsystem Version   : %u\n", optionalHeader.MajorSubsystemVersion);
    printf("Minor Subsystem Version   : %u\n", optionalHeader.MinorSubsystemVersion);
    printf("Win32 Version Value       : 0x%X\n", optionalHeader.Win32VersionValue);
    printf("Size of Image             : %u\n", optionalHeader.SizeOfImage);
    printf("Size of Headers           : %u\n", optionalHeader.SizeOfHeaders);
    printf("CheckSum                  : 0x%X\n", optionalHeader.CheckSum);
    printf("Subsystem                 : 0x%X\n", optionalHeader.Subsystem);
    printf("Dll Characteristics       : 0x%X\n", optionalHeader.DllCharacteristics);
    printf("Size of Stack Reserve     : %u\n", optionalHeader.SizeOfStackReserve);
    printf("Size of Stack Commit      : %u\n", optionalHeader.SizeOfStackCommit);
    printf("Size of Heap Reserve      : %u\n", optionalHeader.SizeOfHeapReserve);
    printf("Size of Heap Commit       : %u\n", optionalHeader.SizeOfHeapCommit);
    printf("Loader Flags              : 0x%X\n", optionalHeader.LoaderFlags);
    printf("Number of RVA and Sizes   : %u\n", optionalHeader.NumberOfRvaAndSizes);

    // Data Directory 출력
    printf("\nData Directory:\n");
    for (int i = 0; i < 16; i++) {
        printf("  Entry %d - Virtual Address: 0x%X, Size: %u\n",
               i, optionalHeader.DataDirectory[i].VirtualAddress, optionalHeader.DataDirectory[i].Size);
    }
}

void printOptionalHeader64(IMAGE_OPTIONAL_HEADER64 optionalHeader) {
    printf("\n***********************\n");
    printf("* Optional Header 정보 (64비트) *\n");
    printf("***********************\n");
    printf("Magic                     : 0x%X\n", optionalHeader.Magic);
    printf("Major Linker Version      : %u\n", optionalHeader.MajorLinkerVersion);
    printf("Minor Linker Version      : %u\n", optionalHeader.MinorLinkerVersion);
    printf("Size of Code              : %u\n", optionalHeader.SizeOfCode);
    printf("Size of Initialized Data  : %u\n", optionalHeader.SizeOfInitializedData);
    printf("Size of Uninitialized Data: %u\n", optionalHeader.SizeOfUninitializedData);
    printf("Address of Entry Point    : 0x%X\n", optionalHeader.AddressOfEntryPoint);
    printf("Base of Code              : 0x%X\n", optionalHeader.BaseOfCode);
    printf("Image Base                : 0x%lX\n", optionalHeader.ImageBase);
    printf("Section Alignment         : %u\n", optionalHeader.SectionAlignment);
    printf("File Alignment            : %u\n", optionalHeader.FileAlignment);
    printf("Major Operating System Version : %u\n", optionalHeader.MajorOperatingSystemVersion);
    printf("Minor Operating System Version : %u\n", optionalHeader.MinorOperatingSystemVersion);
    printf("Major Image Version       : %u\n", optionalHeader.MajorImageVersion);
    printf("Minor Image Version       : %u\n", optionalHeader.MinorImageVersion);
    printf("Major Subsystem Version   : %u\n", optionalHeader.MajorSubsystemVersion);
    printf("Minor Subsystem Version   : %u\n", optionalHeader.MinorSubsystemVersion);
    printf("Win32 Version Value       : 0x%X\n", optionalHeader.Win32VersionValue);
    printf("Size of Image             : %u\n", optionalHeader.SizeOfImage);
    printf("Size of Headers           : %u\n", optionalHeader.SizeOfHeaders);
    printf("CheckSum                  : 0x%X\n", optionalHeader.CheckSum);
    printf("Subsystem                 : 0x%X\n", optionalHeader.Subsystem);
    printf("Dll Characteristics       : 0x%X\n", optionalHeader.DllCharacteristics);
    printf("Size of Stack Reserve     : %llu\n", optionalHeader.SizeOfStackReserve);
    printf("Size of Stack Commit      : %llu\n", optionalHeader.SizeOfStackCommit);
    printf("Size of Heap Reserve      : %llu\n", optionalHeader.SizeOfHeapReserve);
    printf("Size of Heap Commit       : %llu\n", optionalHeader.SizeOfHeapCommit);
    printf("Loader Flags              : 0x%X\n", optionalHeader.LoaderFlags);
    printf("Number of RVA and Sizes   : %u\n", optionalHeader.NumberOfRvaAndSizes);

    // Data Directory 출력
    printf("\nData Directory:\n");
    for (int i = 0; i < 16; i++) {
        printf("  Entry %d - Virtual Address: 0x%X, Size: %u\n",
               i, optionalHeader.DataDirectory[i].VirtualAddress, optionalHeader.DataDirectory[i].Size);
    }
}

// 섹션 헤더 출력 함수
void printSectionHeader(IMAGE_SECTION_HEADER sectionHeader) {
    printf("\n*******************\n");
    printf("* 섹션 헤더 정보  *\n");
    printf("*******************\n");
    printf("Section Name            : %.8s\n", sectionHeader.Name);
    printf("Virtual Size            : %u\n", sectionHeader.VirtualSize);
    printf("Virtual Address         : 0x%X\n", sectionHeader.VirtualAddress);
    printf("Size of Raw Data        : %u\n", sectionHeader.SizeOfRawData);
    printf("Pointer to Raw Data     : 0x%X\n", sectionHeader.PointerToRawData);
    printf("Pointer to Relocations   : 0x%X\n", sectionHeader.PointerToRelocations);
    printf("Pointer to Linenumbers   : 0x%X\n", sectionHeader.PointerToLinenumbers);
    printf("Number of Relocations    : %u\n", sectionHeader.NumberOfRelocations);
    printf("Number of Linenumbers     : %u\n", sectionHeader.NumberOfLinenumbers);
    printf("Characteristics         : 0x%X\n", sectionHeader.Characteristics);
}

//
const char* GetMachineType(uint16_t machine) {
    switch (machine) {
        case 0x014c: return "Intel 386";
        case 0x8664: return "x64";
        case 0x01c0: return "ARM little endian";
        case 0x01c4: return "ARMv7 (Tumb-2)";
        case 0xaa64: return "ARM64 little endian";
        default: return "Unknown machine type";
    }
}


int main() {
    // PE 파일 열기(rb: 바이너리로 읽기)
    FILE *peFile = fopen("sample.exe", "rb");
    // fopen이 NULL 반환: 파일이 열리지 않았다
    if (peFile == NULL) {
        printf("파일을 열 수 없습니다.\n");
        return 1;
    }

    // DOS Header 구조체 선언, 이 구조체에 DOS HEADER의 이미지 불러옴
    IMAGE_DOS_HEADER dosHeader;
    // dosHeader 1개의 크기만큼 데이터 불러와 dosHeader에 저장
    fread(&dosHeader, sizeof(dosHeader), 1, peFile);

    // PE 파일인지 체크하기
    if (dosHeader.e_magic != 0x5A4D) { // MZ는 ASCII코드로 0x4D5A, Little Endian으로 0x5A4D
        printf("PE 파일이 아닙니다.\n");
        return 1;
    }

    // DOS 헤더 정보 출력
    printf("*******************\n");
    printf("* DOS Header의 정보 *\n");
    printf("*******************\n");

    printf("e_magic      : 0x%X\n", dosHeader.e_magic);          // MZ 헤더 시그니처
    printf("e_cblp       : %u\n", dosHeader.e_cblp);             // 마지막 페이지의 바이트 수
    printf("e_cp         : %u\n", dosHeader.e_cp);               // 파일 페이지 수
    printf("e_crlc       : %u\n", dosHeader.e_crlc);             // 재배치 수
    printf("e_cparhdr    : %u\n", dosHeader.e_cparhdr);          // 헤더 크기 (단위: Paragraph)
    printf("e_minalloc   : %u\n", dosHeader.e_minalloc);         // 필요한 최소 추가 메모리
    printf("e_maxalloc   : %u\n", dosHeader.e_maxalloc);         // 최대 추가 메모리
    printf("e_ss         : 0x%X\n", dosHeader.e_ss);             // 초기 SS 레지스터 값
    printf("e_sp         : 0x%X\n", dosHeader.e_sp);             // 초기 SP 레지스터 값
    printf("e_csum       : 0x%X\n", dosHeader.e_csum);           // 체크섬
    printf("e_ip         : 0x%X\n", dosHeader.e_ip);             // 초기 IP 값
    printf("e_cs         : 0x%X\n", dosHeader.e_cs);             // 초기 CS 값
    printf("e_lfarlc     : 0x%X\n", dosHeader.e_lfarlc);         // 재배치 테이블 파일 오프셋
    printf("e_ovno       : %u\n", dosHeader.e_ovno);             // 오버레이 번호
    printf("e_res        : {0x%X, 0x%X, 0x%X, 0x%X}\n",         // 예약된 공간 (배열)
           dosHeader.e_res[0], dosHeader.e_res[1],
           dosHeader.e_res[2], dosHeader.e_res[3]);
    printf("e_oemid      : 0x%X\n", dosHeader.e_oemid);          // OEM ID
    printf("e_oeminfo    : 0x%X\n", dosHeader.e_oeminfo);        // OEM 정보
    printf("e_res2       : {0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X, 0x%X}\n",
           dosHeader.e_res2[0], dosHeader.e_res2[1],             // 추가 예약 공간 (배열)
           dosHeader.e_res2[2], dosHeader.e_res2[3],
           dosHeader.e_res2[4], dosHeader.e_res2[5],
           dosHeader.e_res2[6], dosHeader.e_res2[7],
           dosHeader.e_res2[8], dosHeader.e_res2[9]);
    printf("e_lfanew     : 0x%X\n", dosHeader.e_lfanew);         // PE 헤더의 파일 오프셋

    // DOS Stub 정보 출력
    int dosStubSize = dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER); // DOS Stub의 크기

    printf("\n*******************\n");
    printf("*  DOS Stub의 정보  *\n");
    printf("*******************\n");

    printf("DOS Stub의 크기: %d 바이트\n", dosStubSize);

    printf("\n*******************\n");
    printf("* NT Header의 정보 *\n");
    printf("*******************\n");

    // PE Header 위치로 이동
    fseek(peFile, dosHeader.e_lfanew, SEEK_SET);

    // PE Signature 읽기
    uint32_t signature;
    fread(&signature, sizeof(signature), 1, peFile);

    if (signature != 0x00004550) { // "PE\0\0" 시그니처 확인
        printf("유효한 PE 파일이 아닙니다.\n");
        fclose(peFile);
        return 1;
    }
    printf("PE Signature            : 0x%X\n", signature);

    // File Header 읽기
    IMAGE_FILE_HEADER fileHeader;
    fread(&fileHeader, sizeof(fileHeader), 1, peFile);

    printf("Machine                 : 0x%X (%s)\n", fileHeader.Machine, GetMachineType(fileHeader.Machine)); // 대상 머신 아키텍처
    printf("Number of Sections      : %u\n", fileHeader.NumberOfSections);       // 섹션의 개수
    printf("Time Date Stamp         : 0x%X\n", fileHeader.TimeDateStamp);        // 파일 생성 시간
    printf("Pointer to Symbol Table : 0x%X\n", fileHeader.PointerToSymbolTable); // 심볼 테이블의 파일 오프셋
    printf("Number of Symbols       : %u\n", fileHeader.NumberOfSymbols);        // 심볼의 개수
    printf("Size of Optional Header : %u\n", fileHeader.SizeOfOptionalHeader);   // Optional Header 크기
    printf("Characteristics         : 0x%X\n", fileHeader.Characteristics);      // 파일 속성

    // 32비트와 64비트에 따라 Optional Header 처리
    if (fileHeader.SizeOfOptionalHeader > 0) {
        uint16_t magic;
        fread(&magic, sizeof(magic), 1, peFile);
        fseek(peFile, -sizeof(magic), SEEK_CUR); // Optional Header 전체를 다시 읽기 위해 포인터 되돌림

        if (magic == 0x10B) {
            IMAGE_NT_HEADERS32 ntHeaders32;
            fseek(peFile, dosHeader.e_lfanew, SEEK_SET);
            fread(&ntHeaders32, sizeof(IMAGE_NT_HEADERS32), 1, peFile);
            printf("이 파일은 32비트 PE 파일입니다.\n");
            printOptionalHeader32(ntHeaders32.OptionalHeader);
        } else if (magic == 0x20B) {
            IMAGE_NT_HEADERS64 ntHeaders64;
            fseek(peFile, dosHeader.e_lfanew, SEEK_SET);
            fread(&ntHeaders64, sizeof(IMAGE_NT_HEADERS64), 1, peFile);
            printf("이 파일은 64비트 PE 파일입니다.\n");
            printOptionalHeader64(ntHeaders64.OptionalHeader);
        } else {
            printf("알 수 없는 PE 파일 형식입니다.\n");
        }
    }

    IMAGE_SECTION_HEADER sectionHeader;

    for (int i = 0; i < fileHeader.NumberOfSections; i++) {
        fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, peFile);
        printSectionHeader(sectionHeader);
        printf("\n");
    }

    fclose(peFile);

    return 0;
}
