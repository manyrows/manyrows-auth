# ManyRows Auth

[English](./README.md) | **한국어**

여러분의 앱 앞단에 바로 붙일 수 있는 셀프 호스팅 사용자 인증 시스템입니다.
로그인, 비밀번호 재설정, 이메일 인증, 매직 링크, OAuth(Google, Apple,
Microsoft, GitHub, 카카오, 네이버)와 임의의 OIDC/OAuth2 공급자, 패스키,
세션, 감사 로그, 역할 기반 접근 제어까지 - Postgres와 함께 단일 Go
바이너리로 동작합니다.

한 번 설치하면 여러 앱을 운영할 수 있습니다. 앱들은 사용자 풀(앱 하나
전용 또는 여러 앱이 SSO 방식으로 공유)을 통해 사용자를 공유하며, 각자
고유한 로그인 설정, OAuth 자격 증명, 역할을 가집니다.

> **솔직한 현황.** ManyRows는 개발자 한 명이 만들고 있습니다. 현재
> 프로덕션에서 실제로 운영 중이며 -
> [DrumKingdom.com](https://drumkingdom.com)의 로그인을 담당하고
> 있습니다 - 다만 QA 팀도, SLA도 없고, 버그가 없다고 주장하지도
> 않습니다. 중요한 서비스 앞에 두기 전에 직접 돌려 보고, 충분히
> 두드려 보고, 믿을 만한지 스스로 확인하세요. 뭔가 깨지거나 이상하게
> 느껴진다면, 그건 제가 꼭 듣고 싶은 버그입니다.
>
> **함께 만들어 주세요.** 이슈, 재현 사례, PR 모두 진심으로
> 환영합니다 - 인증 시스템을 단단하게 만드는 건 결국 실제 사용입니다.
> 거의 맞는데 딱 들어맞지 않는 부분이 있다면 알려 주세요. 그런 피드백이
> 그 무엇보다 로드맵을 움직입니다.
>
> **왜 오픈 소스인가.** 인증은 보안에 결정적인 인프라입니다 - 사용자의
> 자격 증명을 블랙박스에 맡겨야 할 이유가 없습니다. 오픈 소스이기에
> 누구나 바이너리가 정확히 무엇을 하는지 감사할 수 있고, 벤더 종속 없이
> 셀프 호스팅할 수 있으며, 제가 떠나더라도 포크할 수 있습니다.
> AGPL-3.0이 이를 보장합니다. 해당 조건이 맞지 않는 경우 상용
> 라이선스도 제공합니다(*라이선스* 참고).
>
> **데이터는 여러분의 것.** 여러분의 Postgres입니다. 사용자, 세션,
> 감사 로그를 일반 SQL로 직접 조회하고, 조인하고, 내보내고, 그 위에
> 무언가를 만들 수 있습니다. 독점 API도, 속도 제한이 걸린 대시보드도,
> 내보내기 수수료도 여러분과 여러분의 데이터 사이를 가로막지 않습니다.

---

## 빠른 시작 (Docker)

```bash
git clone <this-repo>
cd manyrows
cp .env.example .env       # 값을 수정하세요 (특히 MANYROWS_FROM_EMAIL)
docker compose up -d
```

`http://localhost:8080`을 여세요. 가장 먼저 등록한 사람이
슈퍼 관리자가 됩니다 - 그 이후에는 가입 절차가 없으므로, 설치를 외부에
노출하기 전에 먼저 차지하세요.

노출 전에 차지할 수 없는 상황(CI 배포, 느린 첫 부팅 등)이라면
`docker compose up` 전에 `.env`에
`MANYROWS_SUPER_ADMIN_EMAIL=you@yourcompany.com`을 설정하세요. 부팅
시점에 슬롯이 미리 예약되어 정확히 그 이메일만 첫 등록을 완료할 수
있습니다 - 설치를 훑고 다니는 무작위 스캐너는 차지할 수 없습니다.

부팅 과정을 지켜보려면:

```bash
docker compose logs -f web
```

전체를 중지하려면 (데이터는 `manyrows-db` 볼륨에 보존됩니다):

```bash
docker compose down
```

---

## 제공 기능

- **앱별 로그인 방식**: 비밀번호, OTP 코드, 매직 링크, OAuth
  (Google / Apple / Microsoft / GitHub / 카카오 / 네이버), 임의의
  OIDC/OAuth2 공급자, 패스키.
- **자체 ID 공급자 연결(Bring-your-own IdP)** - 기본 제공되는 6개
  소셜 로그인 외에, 어떤 OpenID Connect 또는 OAuth2 공급자든 앱별로
  관리자 UI에서 연결할 수 있습니다(Okta, Auth0, Keycloak, Entra/Azure
  AD, GitLab, Discord 등). issuer URL(또는 명시적 엔드포인트)과
  클라이언트 자격 증명만 붙여 넣으면 됩니다 - 코드도, 릴리스도
  필요 없습니다. 기업용 SSO부터 롱테일까지 커버합니다. PKCE + nonce,
  서명/issuer/audience 검증, https 전용 엔드포인트가 자동으로
  강제됩니다.
- **워크스페이스 + 프로젝트 + 앱 계층 구조** - 하나의 ManyRows 설치가
  환경(dev / staging / prod)을 프로젝트로, 프로젝트를 워크스페이스로
  묶어 관리합니다.
- **역할 기반 접근 제어** - 프로젝트별 권한과 역할, 가입 시 기본 역할
  자동 부여.
- **조직(멀티 테넌트)** - 앱별 옵트인: 최종 사용자가 조직(각자의
  테넌트)에 소속되고, 한 사용자가 여러 조직에 가입할 수 있으며, 각
  조직에서 등급(`owner` / `admin` / `member`)을 가집니다. 역할과
  권한은 사용자의 활성 조직 안에서 해석되고 요청마다 재검증되므로,
  제거된 멤버나 보관 처리된 조직은 즉시 접근을 잃습니다. 조직, 멤버,
  이메일 초대를 서버 API로 백엔드에서 프로비저닝하거나 관리자
  대시보드에서 관리할 수 있습니다.
- **세션 관리** - 앱별 세션 TTL, 쿠키 도메인 제어, IP 허용 목록,
  CORS 오리진 목록, 세션 폐기.
- **감사 로그** - 모든 인증 이벤트가 워크스페이스/앱별로 기록되고,
  관리자 AuthLogs 화면에서 필터링할 수 있습니다.
- **임베드 가능한 최종 사용자 UI** (`@manyrows/appkit-react`) - React
  컴포넌트 하나만 넣으면 완전히 연결된 로그인 화면이 만들어집니다.
- **백엔드 SDK** - Go, Node, Python, Java 제공 - 최종 사용자 JWT를
  로컬에서 검증하고, 여러분의 백엔드에서 서버 API(사용자, 역할, 권한)를
  호출할 수 있습니다. [서버 SDK](#서버-sdk) 참고.
- **OpenID Connect 공급자** - 어떤 앱이든 표준 준수 OIDC로 노출할 수
  있습니다. 기성 라이브러리(next-auth, passport-openidconnect,
  Spring Security 등)가 앱별 디스커버리 URL만 가리키면 연동됩니다 -
  ManyRows SDK가 필요 없습니다.

---

## 스크린샷

<p align="center">
  <img src="docs/screenshots/sign-in.png" width="760" alt="최종 사용자 로그인 (AppKit)"><br><br>
  <img src="docs/screenshots/admin-dashboard.png" width="760" alt="관리자 대시보드"><br><br>
  <img src="docs/screenshots/auth-logs.png" width="760" alt="인증 로그">
</p>

---

## 설정

모든 설정값은 `MANYROWS_*` 접두사가 붙은 환경 변수입니다. 기본값을
포함한 전체 목록은 `.env.example`에 있습니다. 셀프 호스팅에 최소한으로
필요한 설정은 `MANYROWS_FROM_EMAIL` 하나뿐이며, 나머지는 모두 합리적인
기본값을 갖고 있습니다.

알아 두면 좋은 항목들:

| 변수                                              | 기본값 | 비고 |
|---------------------------------------------------|---|---|
| `DATABASE_URL` 또는 `MANYROWS_DATABASE_URL`       | (필수) | Postgres 연결 문자열. |
| `MANYROWS_FROM_EMAIL`                             | (없음) | 발신 메일(관리자 등록, 비밀번호 재설정, 매직 링크)의 보낸 사람 주소. **프로덕션 필수** - From이 비어 있으면 이메일 서비스가 발송을 거부하고 오류를 로깅합니다. DKIM/SPF를 통과하도록 자체 도메인의 주소를 사용하세요. |
| `MANYROWS_BASE_URL`                               | (자동 고정) | 첫 `/admin/register` 시 자동으로 고정됩니다. 알려진 리버스 프록시 뒤에서는 명시적으로 설정하세요. |
| `MANYROWS_DB_SCHEMA`                              | `manyrows` | Postgres 스키마. `manyrows`가 데이터베이스의 다른 것과 충돌하면 변경하세요. |
| `MANYROWS_SMTP_HOST`/`PORT`/`USERNAME`/`PASSWORD` | (없음) | 발신 메일. 설정하지 않으면 메일이 stdout에 로깅됩니다. |
| `MANYROWS_TURNSTILE_ENABLED`                      | `false` | 등록/로그인 시 Cloudflare 봇 검증. 기본은 꺼져 있습니다. |

### 데이터베이스 튜닝

풀 기본값은 대부분의 설치에 적합합니다. 이유를 알고 있을 때만
변경하세요.

| 변수 | 기본값 | 비고 |
|---|---|---|
| `MANYROWS_POOL_MAX_CONNS` | `20` | pgxpool의 상한. 바쁜 설치에서는 올리고, PgBouncer 같은 커넥션 풀러 뒤에서는 낮추세요. |
| `MANYROWS_POOL_MIN_CONNS` | (pgx 기본값) | 풀 크기의 하한. 콜드 스타트 지연이 중요할 때 설정하세요. |
| `MANYROWS_POOL_MIN_IDLE_CONNS` | (pgx 기본값) | 버스트에 대비해 미리 데워 둔 유휴 연결. |
| `MANYROWS_POOL_MAX_CONN_IDLE_TIME_SECONDS` | (pgx 기본값) | 유휴 연결 정리. DB가 연결-분 단위로 과금된다면 조이세요. |
| `MANYROWS_POOL_MAX_CONN_LIFETIME_SECONDS` | (pgx 기본값) | 이 시간(초)이 지나면 모든 연결을 재생성합니다. 장수 TCP 연결을 끊는 로드 밸런서 뒤에서 유용합니다. |
| `MANYROWS_POOL_HEALTH_CHECK_PERIOD_SECONDS` | (pgx 기본값) | pgx가 유휴 연결을 핑해서 데워 두는 주기. |
| `MANYROWS_DB_STATEMENT_TIMEOUT_SECONDS` | (서버 기본값 - 보통 꺼짐) | 모든 풀 연결에 설정되는 Postgres `statement_timeout`. 쿼리 하나가 서버에 의해 취소되기 전까지 쓸 수 있는 벽시계 시간을 제한합니다. **설정을 강력히 권장합니다**(30초로 시작) - 폭주 쿼리가 워커를 영원히 붙잡는 것을 막는 안전장치입니다. |
| `MANYROWS_DB_CONNECT_TIMEOUT_SECONDS` | (pgx 기본값 - 무한 대기) | 새 풀 연결의 TCP+TLS 핸드셰이크 제한 시간. 부팅 경쟁 중 DB IP가 흔들릴 수 있는 환경(Fly, Render)에서 설정하면, 시작이 멈춰 있는 대신 시끄럽게 실패합니다. 10초가 합리적인 값입니다. |
| `MANYROWS_DB_APPLICATION_NAME` | `manyrows` | Postgres의 `application_name` GUC로 보고되며 `pg_stat_activity` / `pg_stat_statements`에서 보입니다. 한 클러스터에 여러 설치를 올릴 때 배포별로 변경하세요(`manyrows-prod`, `manyrows-staging`). |
| `MANYROWS_DB_SKIP_MIGRATIONS` | `false` | `true`로 설정하면 부팅 시 goose를 건너뜁니다. 스키마를 바이너리 롤아웃과 분리해 적용하는 2단계 배포에서 사용합니다 - 새 바이너리가 이전 배포에서 이미 실행한 마이그레이션을 다시 경쟁하지 않고 부팅합니다. |

첫 부팅 시 자동 생성(설정 불필요): HMAC 키, 암호화 키, OTP 페퍼.
`system_secrets`에 저장되어 이후 부팅에서 재사용됩니다.

---

## 프로덕션 배포

ManyRows는 관리자 UI와 AppKit 런타임이 내장된 단일 정적 바이너리로
제공됩니다 - 사이드카도, 에셋 서버도 없습니다 - 그래서 프로덕션
이야기는 짧습니다: TLS를 종료하는 프록시 뒤에서 실행하고 Postgres에
연결하면 됩니다. 번들된 **Docker Compose** 스택, **단독 컨테이너**,
**Heroku** 모두 프로덕션급 경로입니다(아래
[배포 경로](#배포-경로) 참고) - 여러분의 인프라에 맞는 것을
고르세요.

무엇을 고르든 다음 다섯 가지를 하세요:

1. **상류에서 TLS 종료** - Caddy, Traefik, nginx + certbot,
   Cloudflare 프록시, 또는 플랫폼의 로드 밸런서. ManyRows는 프록시
   뒤에서 평문 HTTP로 통신합니다.
2. **`X-Forwarded-Proto: https` 전달** - 쿠키에 `Secure` 플래그가
   붙고 리다이렉트 대상이 올바르게 만들어지도록.
3. **`MANYROWS_BASE_URL` 설정** - 서비스 개시 전에 정식 호스트명으로
   설정하세요(또는 첫 `/admin/register`가 요청에서 고정하도록 두세요).
4. **`manyrows-db` 영속화** - 프로덕션에서는 관리형 Postgres를
   권장합니다. 번들된 compose Postgres를 그대로 쓴다면 볼륨을
   백업하세요.
5. **커스텀 도메인 + 쿠키 범위** - `auth.yourdomain.com`을 ManyRows에
   연결해 쿠키가 여러분의 앱과 퍼스트파티가 되도록 하세요. 관리자
   UI의 앱별 설정 두 가지:
   - *App → Security → Custom Domain* - **Auth domain**을 설정하세요
     (예: `auth.drumkingdom.com`). 자세한 런북은 해당 화면에 있습니다.
   - *App → Security → Session transport → Enable cookies → Cookie
     domain* - 이 값을 **등록 가능한 상위 도메인**으로 설정하세요
     (`auth.drumkingdom.com` → `drumkingdom.com`). 건너뛰면 세션
     쿠키가 인증 서브도메인에만 한정되어, 앱 자체 도메인에서 보내는
     요청에는 전송되지 않습니다.

### 배포 경로

아래의 모든 경로는 같은 이미지를 실행하고 같은 환경 변수를
읽습니다([설정](#설정) 참고). 실질적인 차이는 컨테이너를 누가
실행하고 Postgres가 어디에 있느냐뿐입니다.

> **`MANYROWS_BASE_URL`에는 자체 도메인을 사용하세요** - 앱의 등록
> 가능한 도메인의 서브도메인(`auth.yourdomain.com`)이어야 하며,
> 플랫폼의 기본 호스트는 *안 됩니다*. `*.herokuapp.com`, `*.fly.dev`,
> `*.onrender.com`은 Public Suffix List에 올라 있어, 거기서 설정한
> 세션 쿠키는 여러분의 앱과 퍼스트파티로 공유될 수 없습니다 - 그게
> 체크리스트 5번의 핵심입니다. 아래의 모든 예시는
> `auth.yourdomain.com`을 가정합니다.

#### Docker Compose

번들된 `docker-compose.yml`은 단순한 로컬 데모가 아니라 프로덕션
운영이 가능합니다. 실서비스로 가는 두 가지 방법:

- **관리형 Postgres (권장).** `db` 서비스를 제거하고 `DATABASE_URL`을
  관리형 인스턴스(RDS, Cloud SQL, Neon, Supabase 등)로 향하게
  하세요. ManyRows는 로컬 상태를 갖지 않으므로 `web` 서비스는
  무상태가 되어 자유롭게 재시작할 수 있습니다.
- **번들 Postgres.** 소규모 단일 호스트 설치에서는 `db` 서비스를
  유지하되, 기본 `POSTGRES_PASSWORD`를 변경하고(`.env` 기본값은
  `manyrows`) `manyrows-db` 볼륨을 주기적으로 백업하세요.

어느 쪽이든: 실제 `MANYROWS_FROM_EMAIL`과 SMTP 자격 증명을 설정하고,
`web` 서비스를 아래의 리버스 프록시 중 하나 뒤에 두세요. 이미
`unless-stopped`로 재시작하도록 되어 있습니다.

#### 단독 컨테이너

OCI 이미지를 실행할 수 있는 플랫폼이면 어디든 됩니다 - 단순 `docker
run`, Kubernetes, ECS, Cloud Run, 기타 오케스트레이터(Render와
Fly.io는 아래에 전용 레시피가 있습니다):

```bash
docker build -t manyrows .
docker run -d -p 8080:8080 \
  -e DATABASE_URL="postgres://user:pass@host:5432/manyrows?sslmode=require" \
  -e MANYROWS_FROM_EMAIL="auth@yourdomain.com" \
  -e MANYROWS_BASE_URL="https://auth.yourdomain.com" \
  manyrows
```

바이너리는 플랫폼이 `$PORT`를 설정하면 그 포트에 바인딩하고, 없으면
`8080`으로 폴백합니다 - 대부분의 PaaS에서 추가 설정 없이 포트가
자동으로 연결됩니다.

#### Heroku

이미지는 Heroku에 바로 올릴 수 있습니다: `$PORT`를 존중하고 기본
프로필이 `prod`입니다. Heroku의 라우터가 TLS를 종료하고
`X-Forwarded-Proto`를 설정하므로 체크리스트 1-2번은 자동으로
처리됩니다. `auth.yourdomain.com`을 앞단에 둔다면 커스텀 도메인
단계는 여전히 적용됩니다.

**컨테이너 레지스트리** - 가장 간단하며 `Dockerfile`을 재사용합니다:

```bash
heroku create your-manyrows
heroku addons:create heroku-postgresql:essential-0   # DATABASE_URL을 프로비저닝
heroku config:set \
  MANYROWS_FROM_EMAIL="auth@yourdomain.com" \
  MANYROWS_BASE_URL="https://auth.yourdomain.com"
heroku stack:set container
heroku container:push web && heroku container:release web
```

**Platform API를 통한 바이너리 슬러그** - Docker 없이 로컬에서 Linux
바이너리를 빌드해 슬러그로 푸시합니다. 이미 만들어 둔 앱에
릴리스되므로(위의 `heroku create` / `addons:create` / `config:set`
단계를 먼저 실행하고 `stack:set container`만 건너뛰세요), `jq`와
`~/.netrc`의 Heroku 자격 증명(`heroku login`이 기록)이 필요합니다.
먼저 슬러그를 빌드합니다 - UI 번들은 커밋된 `build-ui.sh`에서
나옵니다:

```bash
bash ./build-ui.sh || { echo "build-ui failed"; exit 1; }

cd manyrows-core
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
GOARCH=amd64 GOOS=linux go build -ldflags="-X main.Version=${VERSION}" \
  -o ../app/web start.go
cd ..
tar czf slug.tgz ./app   # Heroku는 최상위 ./app 디렉터리를 기대합니다 → /app/web
```

그다음 슬러그를 생성, 업로드, 릴리스합니다(`AppID`를 여러분의 앱으로
설정):

```bash
AppID='your-heroku-app'

slug=$(curl -s -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/vnd.heroku+json; version=3' \
  -d '{"process_types":{"web":"./web"}}' \
  -n "https://api.heroku.com/apps/$AppID/slugs")

curl -X PUT -H 'Content-Type:' --data-binary @slug.tgz "$(jq -r '.blob.url' <<< "$slug")"

curl -X POST \
  -H 'Accept: application/vnd.heroku+json; version=3' \
  -H 'Content-Type: application/json' \
  -d "{\"slug\":$(jq '.id' <<< "$slug")}" \
  -n "https://api.heroku.com/apps/$AppID/releases"
```

#### Render

Render는 `Dockerfile`로 바로 빌드하고, `$PORT`를 설정하고, 엣지에서
TLS 종료와 `X-Forwarded-Proto` 전달을 처리합니다 - 프록시
체크리스트가 해결됩니다. Postgres를 프로비저닝하고 `DATABASE_URL`을
연결해 주는 `render.yaml` 블루프린트를 커밋하세요:

```yaml
databases:
  - name: manyrows-db
    plan: basic-256mb

services:
  - type: web
    name: manyrows
    runtime: docker
    plan: starter
    healthCheckPath: /health
    envVars:
      - key: DATABASE_URL
        fromDatabase:
          name: manyrows-db
          property: connectionString
      - key: MANYROWS_FROM_EMAIL
        value: auth@yourdomain.com
      - key: MANYROWS_BASE_URL
        sync: false   # 커스텀 인증 도메인으로 설정하세요 (auth.yourdomain.com)
```

그다음 대시보드에서 *New → Blueprint*로 저장소를 가리키세요.
Dockerfile이 `8080`을 EXPOSE하고 바이너리가 `$PORT`를 존중하므로
추가 설정 없이 포트가 연결됩니다.

#### Fly.io

`fly launch`가 `Dockerfile`을 읽고, `EXPOSE 8080`을 `internal_port`로
인식하고, `force_https = true`가 설정된 `fly.toml`을 작성합니다.
Fly가 TLS를 종료하고 `X-Forwarded-Proto`를 전달하므로 프록시
체크리스트가 해결됩니다.

```bash
fly launch --no-deploy              # Dockerfile을 감지하고 fly.toml 작성
fly postgres create                 # 또는 DATABASE_URL을 Supabase/Neon/Fly MPG로
fly postgres attach <pg-app-name>   # DATABASE_URL 시크릿 설정
fly secrets set MANYROWS_FROM_EMAIL=auth@yourdomain.com \
                MANYROWS_BASE_URL=https://auth.yourdomain.com
fly deploy
```

바이너리의 기본 포트(`8080`)가 Fly가 감지한 `internal_port`와
일치하므로 `$PORT` 연결 작업이 없습니다.

### 리버스 프록시 예시

#### Caddy

Let's Encrypt를 통한 자동 TLS 관리. `/etc/caddy/Caddyfile`에 넣고
`systemctl reload caddy`:

```caddyfile
auth.example.com {
    reverse_proxy localhost:8080
}
```

이게 설정의 전부입니다 - Caddy가 `X-Forwarded-For`,
`X-Forwarded-Proto`, `X-Forwarded-Host`를 자동으로 추가합니다.
ManyRows 컨테이너가 다른 호스트에 있다면 `localhost`를 내부 호스트명 /
IP로 바꾸세요.

#### nginx

인증서는 직접 준비하세요(certbot, Let's Encrypt DNS-01, 내부 CA 등
무엇이든). 최소 동작 설정:

```nginx
server {
    listen 80;
    server_name auth.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

`X-Forwarded-Proto $scheme`이 핵심 라인입니다: 이게 없으면 바이너리가
요청이 HTTPS임을 인식하지 못해 세션 쿠키에 `Secure` 플래그가 빠집니다.

### 업그레이드와 백업

- **업그레이드.** 새 이미지를 풀(또는 새 슬러그를 푸시)하고
  재시작하세요. 스키마 마이그레이션은 부팅 시 goose가 자동으로
  실행합니다. 스키마를 바이너리와 분리해 적용하는 롤아웃이라면
  마이그레이션을 별도로 한 번 실행하고 새 릴리스에
  `MANYROWS_DB_SKIP_MIGRATIONS=true`를 설정해 재경쟁 없이 부팅하게
  하세요.
- **백업.** 관리형 Postgres는 자동 스냅샷을 제공합니다 - 활용하세요.
  번들된 compose Postgres에서는 `pg_dump`를 스케줄에 걸어 두세요.
  자동 생성된 HMAC/암호화 키와 OTP 페퍼는 데이터베이스
  (`system_secrets`)에 저장되므로 Postgres 백업이 전부를 담습니다 -
  따로 저장할 키스토어가 없습니다.
- **헬스 체크.** 플랫폼의 liveness/readiness 프로브를 `/health`로
  향하게 하세요(실행 중인 빌드 버전도 보고합니다).

---

## 앱에 로그인 붙이기 (AppKit)

로그인 화면을 직접 만들 필요가 없습니다. ManyRows는 **AppKit**을
제공합니다 - 여러분의 설치와 통신하는 드롭인 최종 사용자 인증
UI(로그인, 회원가입, OTP 인증, 비밀번호 재설정, 프로필)입니다.
React용 선택적 편의 레이어이며(프레임워크가 없어도 쓸 수 있는
런타임도 있습니다), 완전한 제어를 원하면 Client REST API를 직접
호출하세요. 전체 레퍼런스 - 모든 prop, 훅, 테마, 인증 라우트 처리,
REST API - 는 **<https://manyrows.com/docs>**에 있습니다.

> **CORS - 필수.** AppKit은 *여러분 앱의* 오리진에서 ManyRows를
> 호출하므로, 관리자 UI(Apps 페이지)에서 앱의 허용 CORS 오리진에
> 여러분의 도메인(예: `https://yourapp.com`)을 추가하세요 - 그러지
> 않으면 브라우저가 모든 요청을 차단합니다.

**React** - `npm i @manyrows/appkit-react`:

```tsx
import { AppKit, AppKitAuthed, useUser } from "@manyrows/appkit-react";

function MyApp() {
  const user = useUser();
  return <p>Welcome, {user?.name || user?.email}</p>;
}

export default function Page() {
  return (
    <AppKit
      workspace="your-workspace"
      appId="your-app-id"
      src="https://auth.yourdomain.com/appkit/assets/appkit.js"
    >
      <AppKitAuthed fallback={null}>
        <MyApp />
      </AppKitAuthed>
    </AppKit>
  );
}
```

필수 값은 `workspace`와 `appId`뿐입니다. 셀프 호스팅 중이므로 `src`
prop을 여러분 설치의 런타임 URL로 설정하세요 - 그러지 않으면
AppKit이 기본으로 호스티드(manyrows.com) 런타임을 로드합니다.

**React 없이** - 런타임을 로드하고 `window.ManyRows.AppKit`을 직접
다루세요:

```html
<script src="https://auth.yourdomain.com/appkit/assets/appkit.js" defer></script>
<div id="manyrows-app"></div>
<script>
  window.addEventListener("load", () => {
    window.ManyRows.AppKit.init({
      containerId: "manyrows-app",
      workspace: "your-workspace",
      appId: "your-app-id",
      onState: (s) => {
        if (s.status === "authenticated") {
          console.log("user:", s.appData?.account?.email, "token:", s.jwtToken);
        }
      },
    });
  });
</script>
```

런타임은 여러분의 바이너리가 `/appkit/assets/appkit.js`에서 직접
제공합니다(내장 - 추가로 배포할 것이 없습니다).

---

## 서버 SDK

앱의 **백엔드** 쪽에서는 공식 SDK가 서버 간 API(사용자 조회, 역할,
권한, 설정 전달)를 감싸고, 여러분 설치의 JWKS로 최종 사용자 JWT를
로컬에서 검증합니다 - ManyRows로의 요청별 왕복이 없습니다. Go SDK는
웹훅 서명 검증도 함께 제공합니다.

| 언어              | 저장소                                                              | 설치 |
|-------------------|--------------------------------------------------------------------|---|
| Go                | [manyrows-auth-go](https://github.com/manyrows/manyrows-auth-go)         | `go get github.com/manyrows/manyrows-auth-go` |
| Node / TypeScript | [manyrows-auth-node](https://github.com/manyrows/manyrows-auth-node)     | 소스에서 설치 - 저장소 참고 |
| Python            | [manyrows-auth-python](https://github.com/manyrows/manyrows-auth-python) | `pip install git+https://github.com/manyrows/manyrows-auth-python.git` |
| Java              | [manyrows-auth-java](https://github.com/manyrows/manyrows-auth-java)     | 소스에서 설치 (Java 17+) - 저장소 참고 |

이들은 선택 사항입니다: 브라우저 쪽은 AppKit이 처리하고, 표준 OIDC
클라이언트도 모두 동작합니다(아래 참고). 백엔드가 자기 언어로 토큰을
검증하거나 사용자, 역할, 권한을 읽어야 할 때 SDK를 사용하세요. 각
저장소의 README에 공식 설치 및 사용 문서가 있습니다.

---

## OpenID Connect로 연동하기

AppKit SDK 대신 표준 준수 OIDC 클라이언트 라이브러리를 쓰고 싶다면,
ManyRows는 각 앱을 OpenID Connect 공급자로 노출합니다. 디스커버리,
authorize, token, userinfo, end-session 엔드포인트가 모두 내장되어
있고, PKCE는 필수(S256만 허용)이며, confidential(`client_secret`
사용)과 public(PKCE 전용) 클라이언트 모드를 모두 지원합니다.

*App → Auth methods → OIDC*에서 설정하세요: 토글을 켜고, 필요하면
`client_secret`을 생성하고(한 번만 표시됩니다 - 그때 복사하세요),
RP의 콜백 URL을 redirect-URI 허용 목록에 추가하세요. 관리자 탭이
RP 라이브러리에 필요한 세 가지 값을 보여 줍니다:

| 필드 | 값 패턴 |
|---|---|
| Discovery URL | `https://<auth-domain>/.well-known/openid-configuration` |
| Client ID | 앱의 UUID |
| Client Secret | 서버 측에서 생성; 대화상자에서 한 번만 복사 가능 |

표준 OIDC 클라이언트를 디스커버리 URL로 향하게 하면 자동으로
설정됩니다. `next-auth` 예시:

```ts
import { type AuthOptions } from "next-auth";

export const authOptions: AuthOptions = {
  providers: [
    {
      id: "manyrows",
      name: "ManyRows",
      type: "oauth",
      wellKnown: "https://auth.yourdomain.com/.well-known/openid-configuration",
      clientId: process.env.MANYROWS_CLIENT_ID,      // 앱 UUID
      clientSecret: process.env.MANYROWS_CLIENT_SECRET,
      authorization: { params: { scope: "openid email" } },
    },
  ],
};
```

> **쿠키 전송 모드 필수.** OIDC의 `/authorize` → 로그인 →
> `/authorize/resume` 왕복은 동일 오리진 세션 쿠키에 의존합니다.
> OIDC를 켜기 전에 앱의 *Session transport*를 쿠키로 전환하세요.
> 그렇지 않으면 관리자 UI가 활성화 토글을 막습니다.

AppKit SDK와 공존합니다 - 둘 다 같은 앱에 대해 병렬로 인증할 수
있습니다.

---

## 아키텍처 (한 문단)

단일 Go 바이너리(`manyrows-core`)에 관리자 UI 번들과 최종 사용자
인증 UI 번들이 `//go:embed`로 컴파일되어 들어 있습니다. 외부 의존성은
Postgres가 유일합니다 - 스키마는 `manyrows-core/db/migrations`에
있으며, 부팅 시 `goose`가 설정 가능한 스키마(기본 `manyrows`)에
적용합니다. 관리자 인증은 쿠키 세션을 사용하고, 최종 사용자 인증은
JWT 베어러 토큰(`local` 전송) 또는 HttpOnly 쿠키(`cookie` 전송)를
발급하며, 앱별로 선택할 수 있습니다.

---

## 설계 노트

비자명한 결정들의 *이유* - 비밀번호 해싱, DPoP 바인딩 리프레시 토큰,
이메일 인증 기반 계정 연결, 저장 시 시크릿 암호화, 그리고 의도적으로
뺀 "표준" 기능들 - 은
[`docs/design-notes.md`](docs/design-notes.md)에 정리되어 있습니다.

---

## 개발

```bash
# 소스에서 실행 (개발 모드, UI 핫 리로드):
cd manyrows-ui && npm install && npm run dev   # 터미널 하나에서
cd manyrows-core && go run start.go            # 다른 터미널에서

# 모든 API 테스트 실행 (전용 테스트 데이터베이스 필요):
export TEST_DATABASE_URL="postgres://postgres:postgres@localhost:5432/manyrows_test"
cd manyrows-core
go test ./api/... -count=1

# 특정 테스트 실행:
go test -v ./api/... -run "TestCreateProject" -count=1
```

저장소는 루트의 npm 워크스페이스이므로, 최상위에서 `npm install` 한
번이면 `manyrows-ui`와 `appkit-ui`의 의존성을 모두 받습니다.
`appkit-react`(배포되는 고객용 SDK)는 독립적입니다 - 워크스페이스에
속하지 않고 서버 빌드/실행에도 필요 없습니다. 작업할 때는 의존성을
따로 설치하세요.

---

## 라이선스

[GNU Affero General Public License v3.0](./LICENSE) (AGPL-3.0).

자유롭게 셀프 호스팅하고, 수정하고, 재배포할 수 있습니다. 수정한
버전을 네트워크 서비스로 운영한다면 변경 사항도 AGPL-3.0으로 공개해야
합니다 - AGPL 특유의 SaaS 허점 차단 조항입니다.

AGPL 조건으로 배포할 수 없는 조직을 위해 요청 시 상용 라이선스를
제공합니다.
