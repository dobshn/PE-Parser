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

    printf("Machine                 : 0x%X\n", fileHeader.Machine);              // 대상 머신 아키텍처
    printf("Number of Sections      : %u\n", fileHeader.NumberOfSections);       // 섹션의 개수
    printf("Time Date Stamp         : 0x%X\n", fileHeader.TimeDateStamp);        // 파일 생성 시간
    printf("Pointer to Symbol Table : 0x%X\n", fileHeader.PointerToSymbolTable); // 심볼 테이블의 파일 오프셋
    printf("Number of Symbols       : %u\n", fileHeader.NumberOfSymbols);        // 심볼의 개수
    printf("Size of Optional Header : %u\n", fileHeader.SizeOfOptionalHeader);   // Optional Header 크기
    printf("Characteristics         : 0x%X\n", fileHeader.Characteristics);      // 파일 속성

    fclose(peFile);

    return 0;
}
