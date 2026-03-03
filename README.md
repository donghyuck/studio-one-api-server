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

## 로컬 DB (Docker, Windows 권장)

### 준비 사항
- Windows 10/11
- Docker Desktop 설치 및 실행(WSL2 backend 권장)
- 포트 `5432`가 비어 있어야 함

### 구성 내용
- Postgres 컨테이너: `studio-one-postgres`
- DB: `studio_db`
- 유저/비번: `studioapi` / `studioapi`
- 스키마: `studioapi`
- pgvector: `CREATE EXTENSION vector` 자동 적용
- 기본 데이터: 일부 모듈은 Flyway SQL에 초기 데이터가 포함될 수 있음(예: security-acl의 `R__sync.sql`은 ACL 관련 seed/sync 수행)
- dev 기본 계정/권한/그룹: `application-dev.yml`에서만 dev seed 마이그레이션이 실행됨(`admin` / `studioapi`, 그룹 `default`, 롤 `ROLE_ADMIN`/`ROLE_MANAGER`)

### 실행 방법 (PowerShell)
```powershell
.\scripts\db-up.ps1
```

### 중지 (데이터 유지)
```powershell
.\scripts\db-down.ps1
```

### 접속 정보
- JDBC: `jdbc:log4jdbc:postgresql://localhost:5432/studio_db`
- Username: `studioapi`
- Password: `studioapi`

## 보안 주의사항
- `gradle.properties`에는 민감정보가 포함될 수 있으므로, 실제 값은 사내 보안 정책에 맞게 관리하세요.
- 예시 값이나 테스트용 키는 운영 환경에 사용하지 마세요.
