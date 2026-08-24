# Security Scanner (TUI)

세 개의 정적 보안 스캐너를 TUI로 통합한 도구입니다.

- 민감정보/시크릿 스캐너 — API 키, 개인키, 비밀번호, `eval`/`exec` 같은 위험한 코드 패턴을 정규식으로 탐지 
- SQL 인젝션 스캐너 — f-string, 문자열 결합, `.format()`으로 만들어진 SQL 쿼리를 AST로 탐지 
- 악성코드 시그니처 스캐너 — 파일 해시(MD5/SHA1/SHA256)를 자체 SQLite DB와 대조 

## 폴더 구조

```
security-scanner/
├── main.py                    # Textual TUI 진입점
├── requirements.txt
└── scanners/
    ├── common.py               # 공통 파일 순회 로직
    ├── secrets_scanner.py
    ├── sql_scanner.py
    └── malware_scanner.py
```

## 설치

```bash
pip install -r requirements.txt
```

## 실행

```bash
python main.py
```

- 취약점 스캔 탭: 검사할 경로를 입력하고 원하는 스캐너(민감정보 / SQL 인젝션 / 악성코드)를 선택한 뒤 "스캔 시작"을 누릅니다.
- 악성코드 DB 관리 탭: 폴더 일괄 등록, CSV(MalwareBazaar 형식) 가져오기, 수동 입력 세 가지 방식으로 악성코드 시그니처 DB를 구축합니다.

## 출력 방식

검사 진행 중에는 어떤 폴더를 검사하는지만 표시됩니다. 스캔 대상이 되는 개별 파일 목록은 출력하지 않으며
실제로 문제가 발견된 파일과 그 내용만 결과로 보여줍니다.

