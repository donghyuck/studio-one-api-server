# Studio One API Server

## 3.x 실행 기준선

`3.x` 서버는 Java 17, Gradle 8.14.5, Spring Boot 4.1.0, Spring AI 2.0.0 및
`studio-api` `3.0.0-rc.1` artifact를 사용한다. 애플리케이션 JSON 경계는 Jackson 3이며
MyBatis Spring Boot Starter 4 계열을 사용한다. 개발 worktree에서 플랫폼 소스를 composite
build로 사용하려면 `-PstudioApiDir=/absolute/path/to/studio-api-3x`를 지정할 수 있다.

2.x와 3.x Studio artifact를 한 runtime classpath에 혼합하지 않는다. 3.x 의존성 검증과
rollback 기준은 platform 저장소의
[3.x 업그레이드 기준선](https://github.com/donghyuck/studio-api/blob/3.x/docs/dev/3x-upgrade-baseline.md)을
따른다.

Spring Boot 4에서는 Flyway 자동구성이 별도 starter로 분리되므로
`spring-boot-starter-flyway`와 대상 DB 모듈을 함께 유지해야 한다. `flyway-core`만 직접
추가하면 migration이 실행되지 않은 채 Hibernate schema validation이 시작될 수 있다.

RAG exact-answer cache는 기본적으로 비활성화되어 있으며 다음 환경변수로 전환한다.

```text
RAG_ANSWER_CACHE_TYPE=none
RAG_ANSWER_CACHE_TTL=5m
RAG_ANSWER_CACHE_NAMESPACE=studio:ai:rag-answer:v2
SPRING_DATA_REDIS_HOST=127.0.0.1
SPRING_DATA_REDIS_PORT=6379
```

Redis를 활성화해도 기존 `@Cacheable` 도메인 객체는 Caffeine에 남는다.
`spring.cache.type=caffeine`은 RAG cache와 별개의 직렬화 경계를 보존하기 위한 설정이므로
제거하지 않는다.

권장 승격 순서는 다음과 같다.

1. `RAG_ANSWER_CACHE_TYPE=none`으로 ApplicationContext, 인증, AI 정보, RAG sync/SSE를 확인한다.
2. Redis 연결과 ACL/TLS를 확인하고 `RAG_ANSWER_CACHE_TYPE=redis`로 재기동한다.
3. 동일 principal/object/evidence 질의에서 `MISS → HIT`를 확인한다.
4. 문서 revision 또는 packed evidence를 변경했을 때 `MISS`인지 확인한다.
5. Redis를 중지해도 provider 경로가 HTTP 200으로 응답하는지 확인한다.

롤백할 때는 먼저 `RAG_ANSWER_CACHE_TYPE=none`으로 되돌린 뒤 2.x artifact와 2.1 property
set을 함께 배포한다. v2 namespace는 이전 Jackson payload와 격리되어 있으므로 cache
때문에 DB rollback을 수행할 필요는 없다. PostgreSQL이 별도 schema를 사용하면
`DEFAULT_SCHEMA`와 JDBC URL의 `currentSchema`가 반드시 같은 schema를 가리켜야 한다.

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
- JDBC: `jdbc:postgresql://localhost:5432/studio_db`
- Username: `studioapi`
- Password: `studioapi`

### JDBC SQL logging

`LOG4JDBC_ENABLED=false`가 기본값이다. 이 상태에서는 `DATASOURCE_URL`이 기존
`jdbc:log4jdbc:` 형식이어도 서버가 일반 JDBC URL과 driver로 변환해 batch SQL 문자열 생성 비용을
피한다. SQL 진단이 필요할 때만 다음과 같이 제한적으로 활성화한다.

```text
LOG4JDBC_ENABLED=true
LOG4JDBC_SQLTIMING_LEVEL=INFO
```

`LOG4JDBC_SQLONLY_LEVEL`, `LOG4JDBC_AUDIT_LEVEL`, `LOG4JDBC_RESULTSET_LEVEL`,
`LOG4JDBC_RESULTSETTABLE_LEVEL`, `LOG4JDBC_CONNECTION_LEVEL`은 기본 `OFF`이며 필요할 때만 켠다.

## 보안 주의사항
- `gradle.properties`에는 민감정보가 포함될 수 있으므로, 실제 값은 사내 보안 정책에 맞게 관리하세요.
- 예시 값이나 테스트용 키는 운영 환경에 사용하지 마세요.
