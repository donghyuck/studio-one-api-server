# Studio One API Server

## gradle.properties 설정 안내

`gradle.properties`에는 빌드/의존성 버전 및 실행에 필요한 환경 설정이 포함됩니다. 아래 항목들을 확인하고, 환경에 맞게 값을 설정하세요.

### 프로젝트/빌드
- `buildGroup`: Maven groupId
- `buildVersion`: 애플리케이션 버전
- `javaVersion`: 사용 JDK 버전

### 라이브러리 버전
- `studioOneVersion`
- `lombokVersion`
- `springBootVersion`
- `postgresqlVersion`
- `apachePdfBoxVersion`
- `apachePoiVersion`
- `log4jdbcLog4j2Version`

### Nexus 저장소
- `nexus.releasesUrl`: 사내 Nexus URL
- `nexus.allowInsecure`: HTTPS 미사용 시 `true`

### 보안/암호화
- `JASYPT_ENCRYPTOR_PASSWORD`: Jasypt 암호화 키

### 메일 설정
- `mail.host`
- `mail.port`
- `mail.user`
- `mail.password`

### 오브젝트 스토리지
- `s3.accessKey`
- `s3.secretKey`

### 외부 API
- `gemini.api.key`

## 보안 주의사항
- `gradle.properties`에는 민감정보가 포함될 수 있으므로, 실제 값은 사내 보안 정책에 맞게 관리하세요.
- 예시 값이나 테스트용 키는 운영 환경에 사용하지 마세요.
