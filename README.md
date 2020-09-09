# snort-assistant
Koreatech CSE 2020 Graduation Project.

## TODO
### UI
- [ ] 왼쪽 영역에 기능 1, 2, 3 선택할 수 있는 타일 형태의 큰 버튼.
- [ ] 오른쪽 영역에 각 기능에 대한 레이아웃 표시.
- [ ] 왼쪽 영역에 스노트 상태
- [ ] 스노트 로그 읽으려면 루트권한 필요
- [ ] 스노트 실행상태 스레드로 실시간 검사.
### Feature 1. Pcap Log Parser.
- [X] 로그 읽어서 리스트나 테이블에 표시 및 차트를 활용한 통계 제공.
- [X] 리스트나 테이블에 표시한 후 버튼을 눌러서 호출하면 차트로 표시.
- [X] 차트는 패킷의 소스 어드레스, 패킷의 유형, 수신 날짜 빈도수로 정렬하여 파이차트로 표시.
  - [X] 차트에 몇개나 보여줄지 그 리밋을 설정할 수 있는 폼 스피너로 구현.
  - [X] 소스 어드레스가 없는("-") 패킷은 제외하고 계산.
- [X] 기본적인 헤더(src, dst) 말고도 페이로드를 팝업 윈도우로 보여줄 수 있도록
  - [ ] 단순 16진수 나열 말고 무엇을 할 수 있는지?
  - [ ] 여러개의 팝업 윈도우로 여러 페이로드를 비교할 수 있도록?
- [X] UI 조정 필요. 화면이 너무 작다. fxml에서 조정할것.
  - [X] 파이차트랑 라디오 옵션이 화면 하단까지 늘어나도록 조정할것.
- [X] 시각 표시 필요. RawPacket 클래스의 Timeval 활용할 수 있을것.
  - [X] 시각 포맷 좀 알아보기.
  - [X] 표시 중 문제가 초 단위로 나뉘니까 차트의 파이가 너무 많아짐. 최소 단위(분, 시, 일)를 정해야 할듯.
- 패킷 종류에 따라 정보를 잘 뽑아내서 저장할 수 있도록 핸들러 적용 필요.
  - [X] 포트번호(SSL: 443) 구분하여 따로 처리. 아니 그냥 포트번호는 유명한 포트는 비교해서 필터링해서 표시하는것도.
- [X] 기본적인 로그 필터링 기능 구현.
  - [X] 여러 필터를 추가한 후에 적용 버튼 눌러서 적용하도록
- PcapLog 클래스에 필드를 딱 지정해두지 않고 HashMap 등으로 유동적으로 필드명과 값을 저장할 수 있게 하려면? >> 정확히는, 이에 대해 팩토리를 생성하려면 어떻게?? 패킷 별로 필드 차이가 많은지 함 보자
- [ ] 스노트 로그를 실시간으로 읽을 수 있는 방법이 있나?(root 권한 등)
- [ ] 컨텍스트 메뉴를 활용해서 해당 ip나 프로토콜을 차단
- [X] 패킷 로딩 비동기 처리. 얼마나 읽어가는지 프로그레스 표시.
- [X] 작업진행중에는 해당 그룹의 노드들 전부 비활성화 및 재활성화.

### Feature 2. Rule Parser.
- [ ] 룰 읽어서 리스트나 테이블에 표시
- [ ] 수정, 편집 후 저장 기능
- [ ] 환경변수($EXTERNAL_NET)를 읽어서 반영할 수 있도록?
- [ ] 정규표현식을 활용하여 파싱을 좀 더 편하게 할수도.
- [ ] Accordion 컨테이너 활용?

### Feature 3. Snort Controller.
- [ ] 스노트 관련 설정 조사, 조작기능 추가.
- [ ] 스노트 켜고 끄기
- [ ] 스노트 configurations 조작할 수 있도록?
