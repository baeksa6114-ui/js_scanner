# JS Security Scanner

공개된 웹사이트의 JavaScript 파일을 수집하고, 보안상 검토가 필요한 단서를 자동으로 탐지하는 Python 기반 OSINT 분석 도구입니다.

## 주요 기능
- 웹사이트의 공개 JavaScript 파일 수집
- API 경로 및 인증정보 관련 문자열 탐지
- Supabase, Firebase 등 외부 서비스 설정 단서 확인
- Source Map 참조 여부 확인
- 탐지 결과를 JSON 형식으로 저장

## 실행 방법

```bash
python test5.py https://example.com/ --out report.json
```

## 활용 목적
공개 JavaScript 파일에 포함된 잠재적 보안 위험 요소를 식별하고, 반복적인 수동 분석 작업을 효율화하기 위해 개발했습니다.

**※ 탐지된 항목은 취약점이 확정된 것이 아니며, 추가적인 수동 검증이 필요합니다.**
