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

int main() {
    // PE 파일 열기(rb: 바이너리로 읽기)
    FILE *peFile = fopen("notepad++.exe", "rb");
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

    fclose(peFile);

    return 0;
}
