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

## 실행 요약

### 필수 준비 사항
- JDK 17 설치
- Gradle Wrapper 사용 가능 상태(`gradlew`, `gradlew.bat`)
- 로컬 또는 접근 가능한 Nexus 저장소(`nexus.releasesUrl`)
- 실행에 필요한 외부 설정 값 준비:
  - `JASYPT_ENCRYPTOR_PASSWORD`
  - 메일 설정(`mail.*`)
  - 오브젝트 스토리지(`s3.*`)
  - 외부 API 키(`gemini.api.key`)

### 실행 방법

#### 개발 환경 (기본값: dev 프로파일)
```bash
./gradlew bootRun
```

#### 로컬 프로파일
```bash
./gradlew bootRun --args='--spring.profiles.active=local'
```

#### 빌드 후 실행
```bash
./gradlew clean build
java -jar build/libs/*.jar --spring.profiles.active=dev
```

## 보안 주의사항
- `gradle.properties`에는 민감정보가 포함될 수 있으므로, 실제 값은 사내 보안 정책에 맞게 관리하세요.
- 예시 값이나 테스트용 키는 운영 환경에 사용하지 마세요.
