cmake_minimum_required(VERSION 3.20)
project(PEParser C)

set(CMAKE_C_STANDARD 11)  # C 표준을 C11로 설정

add_executable(PEParser src/pe_parser.c)  # 실행 파일과 소스 파일 설정