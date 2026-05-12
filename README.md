# Studio One API Server

## gradle.properties 설정 안내

`gradle.properties`에는 빌드/의존성 버전 및 실행에 필요한 환경 설정이 포함됩니다. 아래 항목들을 확인하고, 환경에 맞게 값을 설정하세요.

### 프로젝트/빌드
- `buildGroup`: Maven groupId
- `buildVersion`: 애플리케이션 버전
- `javaVersion`: 사용 JDK 버전
- 하위 호환 키도 지원: `buildApplicationGroup`, `buildApplicationVersion`, `sourceCompatibility`, `targetCompatibility`

### 라이브러리 버전
- `studioOneVersion`
- `lombokVersion`
- `springBootVersion`
- `postgresqlVersion`
- `apachePdfBoxVersion`
- `apachePoiVersion`
- `log4jdbcLog4j2Version`

### studio.one 의존성 해석
- 기본값으로 로컬 Gradle 캐시(`~/.gradle/caches/modules-2/files-2.1`)의 `studio.one` JAR을 폴백으로 사용합니다.
- 사내 Nexus만 강제로 사용하려면 `useStudioLocalCache=false`를 설정하세요.

### Nexus 저장소
- `nexus.releasesUrl`: 기본 Nexus URL
- `nexus.allowInsecure`: HTTPS 미사용 시 `true`
- `scripts/run-dev.sh`는 `.env.local`을 읽고 Gradle을 실행합니다.
- `.env.local`에 `NEXUS_RELEASES_URL`, `NEXUS_ALLOW_INSECURE`, `NEXUS_USERNAME`, `NEXUS_PASSWORD`를 두면 Nexus 설정을 쉽게 바꿀 수 있습니다.
- `.env.local`에 `OPENAI_API_KEY`가 없으면 `run-dev.sh`가 OpenAI 관련 Spring AI 자동설정을 제외하고 실행합니다.
- `.env.local`에 `OPENAI_API_KEY`가 있으면 `SPRING_AI_OPENAI_API_KEY`로 연결해서 OpenAI 모델 자동설정을 사용합니다.
- `.env.local`에 `OPENAI_API_KEY`가 있으면 `OPENAI_PROVIDER_ENABLED=true`를 기본값으로 설정해 OpenAI provider도 함께 활성화합니다.
- `.env.local`에 `GEMINI_API_KEY`가 있으면 `application-dev.yml`에서 Gemini chat/embedding 설정에 공통으로 사용합니다.
- `studio.ai.*`는 provider 선택/활성화와 RAG orchestration을 담당하고, 실제 Gemini/OpenAI/Ollama SDK 옵션은
  `spring.ai.*`가 기준입니다. 예를 들어 Gemini embedding은
  `spring.ai.google.genai.embedding.text.options.model=gemini-embedding-001`과
  `spring.ai.google.genai.embedding.text.options.dimensions=768`을 사용합니다.

### RAG chunking
- `studio-platform-starter-chunking`이 있으면 RAG 인덱싱은 `studio.chunking.*` 설정을 우선 사용합니다.
- 기존 `studio.ai.pipeline.chunk-size`, `studio.ai.pipeline.chunk-overlap`은 chunking starter가 없을 때의 fallback 설정입니다.

### Workspace management API
- `/api/mgmt/workspaces` 계열 API는 `studio-platform-starter-workspace` 의존성과 `studio.features.workspace.enabled=true`, `studio.features.workspace.web.enabled=true` 설정이 필요합니다.
- Flyway에는 `classpath:/schema/workspace/{db}` location이 포함되어야 `TB_PLATFORM_WORKSPACE`, `TB_PLATFORM_WORKSPACE_CLOSURE`, `TB_PLATFORM_WORKSPACE_MEMBER`가 생성됩니다.

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

#### `.env.local`을 읽어서 실행
```bash
./scripts/run-dev.sh
```

#### 프로파일 지정
```bash
./scripts/run-dev.sh local
```

#### 예시 `.env.local`
```bash
NEXUS_RELEASES_URL=http://localhost:8081/repository/maven-releases/
NEXUS_ALLOW_INSECURE=true
NEXUS_USERNAME=...
NEXUS_PASSWORD=...
OPENAI_API_KEY=
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
- 비밀번호 포맷: Spring Security `DelegatingPasswordEncoder` 사용 시 DB의 `password_hash`는 `{bcrypt}...` 같은 prefix가 필요함(dev seed는 해당 포맷으로 저장)
- forums 테이블: `tb_application_forums` 등은 `src/main/resources/schema/forums/postgres/V1100__create_forums_tables.sql`로 생성됨

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
