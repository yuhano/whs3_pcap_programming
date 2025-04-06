# whs3_pcap_programming

## PCAP Programming 과제 개요

본 과제는 C언어를 활용하여 PCAP API를 이용한 패킷 분석 프로그램을 작성하는 것을 목표로 한다. 
Ethernet, IP, TCP 헤더 정보를 추출 및 출력하고, 메시지 내용도 함께 표시하는 기능을 포함한다.

### 주요 구현 내용

- **Ethernet Header**
  - Source MAC Address
  - Destination MAC Address

- **IP Header**
  - Source IP Address
  - Destination IP Address

- **TCP Header**
  - Source Port
  - Destination Port

- **Message**
  - 메시지 데이터도 함께 출력 (너무 길 경우 적절히 자를 것)

### 구현 조건

- **TCP 프로토콜**에 대해서만 처리하며, **UDP는 무시**한다.
- `sniff_improved.c`, `myheader.h` 파일을 참고하여 구현.
- IP 및 TCP 헤더의 **길이 정보**를 정확히 활용하여 올바르게 파싱할 것.

### 컴파일 방법

패킷 캡처를 위해 `libpcap` 라이브러리를 사용하므로, 컴파일 시 해당 라이브러리를 링크해야 한다.

```bash
gcc -o net_parser net_parser.c -lpcap
```