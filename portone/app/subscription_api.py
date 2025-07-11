from fastapi import FastAPI, HTTPException, Header, Request, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
import requests
import jwt
import json
import os
from datetime import datetime
import boto3
from typing import Optional
import logging
import pymysql
from pymysql.cursors import DictCursor
from functools import lru_cache
from jwt.algorithms import RSAAlgorithm

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Portone Subscription API", version="1.0.0")

# CORS 설정
origins = [
    "https://www.highlight.monster",
    "https://api.highlight.monster",
    # 개발 환경에서 프론트엔드가 실행되는 주소가 있다면 여기에 추가해주세요.
    # 예: "http://localhost:3000",
    # 예: "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # 명확한 도메인만 허용
    allow_credentials=True,  # 인증 필요시 True
    allow_methods=["*"],  # 모든 HTTP 메서드 허용
    allow_headers=["*"],  # 모든 헤더 허용
)

# 환경 변수 설정
# 실제 운영 환경에서는 이 값들을 환경 변수로 설정해야 합니다.
IMP_KEY = os.getenv("IMP_KEY", "3310784806446756")
IMP_SECRET = os.getenv(
    "IMP_SECRET",
    "Hw6Zuz69UEbszlwdREABKjrFWKe4Pm2wEEwnraJwVRZTP1nahtKS2B1XgOyOAFfIydLn1EZG0aDcBgE8",
)
RDS_HOST = os.getenv("RDS_HOST", "localhost")
RDS_PORT = int(os.getenv("RDS_PORT", 3306))
RDS_USER = os.getenv("RDS_USER", "root")
RDS_PASSWORD = os.getenv("RDS_PASSWORD", "password")
RDS_DB = os.getenv("RDS_DB", "portone_payments")

COGNITO_USER_POOL_ID = os.getenv(
    "COGNITO_USER_POOL_ID", "ap-northeast-2_xxxxxxxxx"
)  # 실제 User Pool ID로 변경 필요
COGNITO_CLIENT_ID = os.getenv(
    "COGNITO_CLIENT_ID", "your-client-id"
)  # 실제 Client ID로 변경 필요
COGNITO_CLIENT_SECRET = os.getenv(
    "COGNITO_CLIENT_SECRET", "your-client-secret"
)  # 실제 Client Secret으로 변경 필요
COGNITO_DOMAIN = os.getenv(
    "COGNITO_DOMAIN",
    "your-domain.auth.ap-northeast-2.amazoncognito.com",  # 실제 Cognito 도메인으로 변경 필요
)
AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-2")

cognito_client = boto3.client("cognito-idp", region_name=AWS_REGION)


# 환경 변수 검증 함수
def validate_environment_variables():
    """필수 환경 변수가 설정되어 있는지 검증합니다."""
    required_vars = {
        "COGNITO_USER_POOL_ID": COGNITO_USER_POOL_ID,
        "COGNITO_CLIENT_ID": COGNITO_CLIENT_ID,
        "AWS_REGION": AWS_REGION,
    }

    missing_vars = [
        var
        for var, value in required_vars.items()
        if not value or value.startswith("your-") or value.endswith("xxxxxxxxx")
    ]

    if missing_vars:
        logger.error(f"필수 환경 변수가 설정되지 않았습니다: {missing_vars}")
        return False

    # Cognito 시크릿은 선택사항이므로 경고만 출력
    if not COGNITO_CLIENT_SECRET or COGNITO_CLIENT_SECRET.startswith("your-"):
        logger.warning(
            "COGNITO_CLIENT_SECRET이 설정되지 않았습니다. JWT 토큰 검증은 공개키만으로 수행됩니다."
        )

    logger.info("환경 변수 검증 완료")
    return True


# 애플리케이션 시작 시 환경 변수 검증
if not validate_environment_variables():
    logger.error("환경 변수 검증 실패로 인해 애플리케이션을 시작할 수 없습니다.")
    raise RuntimeError("Required environment variables are not properly configured")


# 데이터베이스 연결을 관리하는 함수
def get_db_connection():
    """데이터베이스 연결을 생성하고 반환합니다."""
    try:
        conn = pymysql.connect(
            host=RDS_HOST,
            port=RDS_PORT,
            user=RDS_USER,
            password=RDS_PASSWORD,
            db=RDS_DB,
            charset="utf8mb4",
            cursorclass=DictCursor,
            autocommit=True,
            connect_timeout=10,
        )
        logger.info("DB 연결 성공")
        return conn
    except Exception as e:
        logger.error(f"DB 연결 실패: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")


@lru_cache(maxsize=1)
def get_cognito_public_keys_cached():
    """Cognito 공개키를 캐싱하여 가져옵니다."""
    try:
        response = requests.get(
            f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
        )
        response.raise_for_status()
        logger.info("Cognito 공개키 가져오기 성공")
        return response.json()["keys"]
    except Exception as e:
        logger.error(f"Cognito 공개키 가져오기 실패: {e}")
        return None


def get_cognito_public_keys():
    """캐싱된 Cognito 공개키를 반환합니다."""
    return get_cognito_public_keys_cached()


def verify_jwt_token(token: str):
    """JWT 토큰을 검증하고 페이로드를 반환합니다."""
    try:
        # 토큰 디코딩 전에 헤더 확인
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            logger.warning("토큰 헤더에 'kid'가 없습니다.")
            raise HTTPException(
                status_code=401, detail="Invalid token header: Missing 'kid'"
            )

        # Cognito 공개키 가져오기
        public_keys = get_cognito_public_keys()
        if not public_keys:
            logger.error("공개키를 가져오지 못했습니다.")
            raise HTTPException(
                status_code=500,
                detail="Failed to get public keys for token verification",
            )

        # kid에 해당하는 공개키 찾기
        public_key = None
        for key in public_keys:
            if key["kid"] == kid:
                public_key = RSAAlgorithm.from_jwk(json.dumps(key))
                break

        if not public_key:
            logger.warning(f"토큰의 'kid'({kid})에 해당하는 공개키를 찾을 수 없습니다.")
            logger.info(f"사용 가능한 키들: {[k['kid'] for k in public_keys]}")
            raise HTTPException(
                status_code=401,
                detail="Invalid token key: No matching public key found",
            )

        # JWT 토큰 검증 (Cognito 시크릿 없이도 검증 가능)
        issuer = (
            f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
        )
        logger.info(f"토큰 검증 시도 - Issuer: {issuer}")

        # audience 검증은 선택적으로 수행 (클라이언트 ID가 설정된 경우에만)
        verify_options = {
            "algorithms": ["RS256"],
            "issuer": issuer,
        }

        # COGNITO_CLIENT_ID가 설정되어 있고 기본값이 아닌 경우에만 audience 검증
        if COGNITO_CLIENT_ID and not COGNITO_CLIENT_ID.startswith("your-"):
            verify_options["audience"] = COGNITO_CLIENT_ID

        payload = jwt.decode(token, public_key, **verify_options)
        logger.info("JWT 토큰 검증 성공")
        logger.debug(f"토큰 페이로드: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("토큰 만료: ExpiredSignatureError")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidIssuerError as e:
        logger.warning(f"잘못된 발급자: {e}")
        raise HTTPException(status_code=401, detail="Invalid token issuer")
    except jwt.InvalidAudienceError as e:
        logger.warning(f"잘못된 대상: {e}")
        raise HTTPException(status_code=401, detail="Invalid token audience")
    except jwt.InvalidTokenError as e:
        logger.warning(f"유효하지 않은 토큰: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"토큰 검증 중 예상치 못한 오류 발생: {e}")
        raise HTTPException(
            status_code=401,
            detail="Token verification failed due to an unexpected error",
        )


# 테스트 모드 (개발 환경에서만 사용)
TEST_MODE = os.getenv("TEST_MODE", "false").lower() == "true"


async def get_current_user(
    request: Request, authorization: Optional[str] = Header(None)
):
    """요청 헤더에서 JWT 토큰을 추출하고 현재 사용자 정보를 반환합니다."""
    logger.info(
        f"인증 요청 시작 - Authorization 헤더: {authorization[:50] if authorization else 'None'}..."
    )

    if not authorization or not authorization.startswith("Bearer "):
        logger.warning("Authorization 헤더가 없거나 형식이 잘못되었습니다.")
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing Authorization header. Expected 'Bearer <token>'",
        )

    token = authorization.split(" ")[1]
    logger.info(f"토큰 추출 완료 - 길이: {len(token)}")

    # 테스트 모드에서는 토큰 검증을 우회
    if TEST_MODE:
        logger.warning("테스트 모드: 토큰 검증을 우회합니다.")
        # 테스트용 사용자 정보 반환
        return {
            "user_id": "test-user-id",
            "sub": "test-sub",
            "email": "test@example.com",
            "name": "Test User",
        }

    try:
        payload = verify_jwt_token(token)
        logger.info(
            f"토큰 검증 성공 - 사용자 ID: {payload.get('cognito:username') or payload.get('sub')}"
        )
    except Exception as e:
        logger.error(f"토큰 검증 실패: {e}")
        raise

    user_id = payload.get("cognito:username") or payload.get("sub")
    if not user_id:
        logger.error("토큰 페이로드에서 사용자 ID를 찾을 수 없습니다.")
        logger.error(f"페이로드 내용: {payload}")
        raise HTTPException(
            status_code=500, detail="Could not retrieve user ID from token payload."
        )

    user_info = {
        "user_id": user_id,
        "sub": payload.get("sub"),
        "email": payload.get("email"),
        "name": payload.get("name") or payload.get("cognito:username"),
    }
    logger.info(f"사용자 정보 생성 완료: {user_info}")
    return user_info


def _get_user_data_from_db(user_id: str):
    """데이터베이스에서 사용자 정보를 조회합니다."""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id, email, name, last_login, created_at, updated_at
                FROM users WHERE user_id = %s
                """,
                (user_id,),
            )
            user_data = cursor.fetchone()
            return user_data
    except Exception as e:
        logger.error(f"DB에서 사용자 정보 조회 실패 (user_id: {user_id}): {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve user information from database: {e}",
        )
    finally:
        if conn:
            conn.close()


@app.post("/debug/init-database")
async def init_database():
    """데이터베이스 스키마를 초기화합니다."""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # 1. 사용자 테이블 생성
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id VARCHAR(64) PRIMARY KEY,
                    email VARCHAR(255) NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    sub VARCHAR(255) NOT NULL,
                    last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    INDEX idx_email (email),
                    INDEX idx_sub (sub)
                )
            """
            )

            # 2. 구독 플랜 테이블 생성
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS subscription_plans (
                    plan_id VARCHAR(32) PRIMARY KEY,
                    plan_name VARCHAR(100) NOT NULL,
                    price INT NOT NULL,
                    duration_days INT NOT NULL DEFAULT 30,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """
            )

            # 3. 사용자 구독 테이블 생성
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS user_subscriptions (
                    subscription_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(64) NOT NULL,
                    plan_id VARCHAR(32) NOT NULL,
                    customer_uid VARCHAR(64) NOT NULL,
                    billing_key VARCHAR(64),
                    status ENUM('active', 'cancelled', 'expired', 'payment_failed') DEFAULT 'active',
                    start_date DATE NOT NULL,
                    end_date DATE NOT NULL,
                    next_payment_date DATE,
                    cancel_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                    FOREIGN KEY (plan_id) REFERENCES subscription_plans(plan_id) ON DELETE CASCADE,
                    INDEX idx_user_status (user_id, status),
                    INDEX idx_customer_uid (customer_uid)
                )
            """
            )

            # 4. 결제 내역 테이블 생성
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS payment_history (
                    payment_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id VARCHAR(64) NOT NULL,
                    subscription_id INT,
                    imp_uid VARCHAR(64) NOT NULL,
                    merchant_uid VARCHAR(64) NOT NULL,
                    amount INT NOT NULL,
                    status ENUM('success', 'failed', 'cancelled') DEFAULT 'success',
                    payment_method VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                    FOREIGN KEY (subscription_id) REFERENCES user_subscriptions(subscription_id) ON DELETE SET NULL,
                    INDEX idx_user_id (user_id),
                    INDEX idx_imp_uid (imp_uid),
                    INDEX idx_merchant_uid (merchant_uid)
                )
            """
            )

            # 5. 기본 구독 플랜 데이터 삽입
            cursor.execute(
                """
                INSERT INTO subscription_plans (plan_id, plan_name, price, duration_days, is_active) VALUES
                ('basic', '베이직 플랜', 9900, 30, TRUE),
                ('premium', '프리미엄 플랜', 19900, 30, TRUE)
                ON DUPLICATE KEY UPDATE
                    plan_name = VALUES(plan_name),
                    price = VALUES(price),
                    duration_days = VALUES(duration_days),
                    is_active = VALUES(is_active),
                    updated_at = CURRENT_TIMESTAMP
            """
            )

            # 6. 활성 구독 조회 뷰 생성
            cursor.execute(
                """
                CREATE OR REPLACE VIEW active_subscriptions AS
                SELECT 
                    us.subscription_id,
                    us.user_id,
                    u.name as user_name,
                    u.email as user_email,
                    us.plan_id,
                    sp.plan_name,
                    sp.price,
                    us.status,
                    us.start_date,
                    us.end_date,
                    us.next_payment_date,
                    DATEDIFF(us.end_date, CURDATE()) as remaining_days
                FROM user_subscriptions us
                JOIN users u ON us.user_id = u.user_id
                JOIN subscription_plans sp ON us.plan_id = sp.plan_id
                WHERE us.status = 'active'
            """
            )

            conn.commit()
            logger.info("데이터베이스 스키마 초기화 완료")

            return {
                "status": "success",
                "message": "데이터베이스 스키마가 성공적으로 초기화되었습니다.",
                "tables_created": [
                    "users",
                    "subscription_plans",
                    "user_subscriptions",
                    "payment_history",
                ],
                "view_created": "active_subscriptions",
                "plans_inserted": ["basic", "premium"],
            }

    except Exception as e:
        logger.error(f"데이터베이스 초기화 실패: {e}")
        if conn:
            conn.rollback()
        return {"status": "error", "error": str(e)}
    finally:
        if conn:
            conn.close()


@app.get("/debug/database")
async def debug_database():
    """데이터베이스 연결 및 스키마 상태를 확인합니다."""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # 테이블 존재 여부 확인
            cursor.execute(
                """
                SELECT TABLE_NAME 
                FROM INFORMATION_SCHEMA.TABLES 
                WHERE TABLE_SCHEMA = %s
            """,
                (RDS_DB,),
            )
            tables = [row["TABLE_NAME"] for row in cursor.fetchall()]

            # 구독 플랜 데이터 확인
            cursor.execute("SELECT COUNT(*) as count FROM subscription_plans")
            plans_result = cursor.fetchone()
            plans_count = plans_result["count"] if plans_result else 0

            # 사용자 수 확인
            cursor.execute("SELECT COUNT(*) as count FROM users")
            users_result = cursor.fetchone()
            users_count = users_result["count"] if users_result else 0

            # 활성 구독 수 확인
            cursor.execute(
                "SELECT COUNT(*) as count FROM user_subscriptions WHERE status = 'active'"
            )
            subscriptions_result = cursor.fetchone()
            active_subscriptions_count = (
                subscriptions_result["count"] if subscriptions_result else 0
            )

            # 결제 내역 수 확인
            cursor.execute("SELECT COUNT(*) as count FROM payment_history")
            payments_result = cursor.fetchone()
            payments_count = payments_result["count"] if payments_result else 0

            # 최근 구독 플랜 정보
            cursor.execute(
                "SELECT plan_id, plan_name, price, duration_days FROM subscription_plans WHERE is_active = TRUE"
            )
            plans = cursor.fetchall()

            return {
                "status": "connected",
                "database": RDS_DB,
                "host": RDS_HOST,
                "tables": tables,
                "counts": {
                    "subscription_plans": plans_count,
                    "users": users_count,
                    "active_subscriptions": active_subscriptions_count,
                    "payments": payments_count,
                },
                "plans": plans,
            }

    except Exception as e:
        logger.error(f"데이터베이스 디버깅 실패: {e}")
        return {
            "status": "error",
            "error": str(e),
            "database": RDS_DB,
            "host": RDS_HOST,
        }
    finally:
        if conn:
            conn.close()


@app.get("/debug/token")
async def debug_token_info(authorization: Optional[str] = Header(None)):
    """토큰 정보를 디버깅용으로 확인합니다."""
    if not authorization or not authorization.startswith("Bearer "):
        return {"error": "Authorization header missing or invalid"}

    token = authorization.split(" ")[1]

    try:
        # 토큰 헤더 확인
        header = jwt.get_unverified_header(token)

        # 토큰 페이로드 확인 (검증 없이)
        import base64

        parts = token.split(".")
        if len(parts) == 3:
            payload_part = parts[1]
            # 패딩 추가
            payload_part += "=" * (4 - len(payload_part) % 4)
            payload = json.loads(base64.b64decode(payload_part))
        else:
            payload = {"error": "Invalid token format"}

        return {
            "header": header,
            "payload": payload,
            "token_length": len(token),
            "environment": {
                "cognito_user_pool_id": COGNITO_USER_POOL_ID,
                "cognito_client_id": COGNITO_CLIENT_ID,
                "aws_region": AWS_REGION,
            },
        }
    except Exception as e:
        return {"error": f"Token parsing failed: {str(e)}"}


@app.get("/health")
async def health_check():
    """헬스체크 엔드포인트 - 환경 변수 및 연결 상태 확인"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "environment": {
            "cognito_user_pool_id": COGNITO_USER_POOL_ID,
            "cognito_client_id": COGNITO_CLIENT_ID,
            "aws_region": AWS_REGION,
            "rds_host": RDS_HOST,
            "rds_db": RDS_DB,
        },
        "checks": {},
    }

    # Cognito 공개키 확인
    try:
        public_keys = get_cognito_public_keys()
        health_status["checks"]["cognito_public_keys"] = {
            "status": "success" if public_keys else "failed",
            "keys_count": len(public_keys) if public_keys else 0,
        }
    except Exception as e:
        health_status["checks"]["cognito_public_keys"] = {
            "status": "error",
            "error": str(e),
        }

    # 데이터베이스 연결 확인
    try:
        conn = get_db_connection()
        conn.close()
        health_status["checks"]["database"] = {"status": "success"}
    except Exception as e:
        health_status["checks"]["database"] = {"status": "error", "error": str(e)}
        health_status["status"] = "unhealthy"

    return health_status


@app.get("/subscription/plans")
async def get_subscription_plans():
    """활성화된 구독 플랜 목록을 조회합니다."""
    conn = None
    try:
        conn = get_db_connection()  # 올바른 연결 사용
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM subscription_plans WHERE is_active = TRUE")
            plans = cursor.fetchall()
        logger.info("구독 플랜 조회 성공")
        return {"plans": plans}
    except Exception as e:
        logger.error(f"구독 플랜 조회 실패: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to get subscription plans: {e}"
        )
    finally:
        if conn:
            conn.close()


@app.get("/user/me")
async def get_current_user_info(
    current_user: dict = Depends(
        get_current_user
    ),  # Depends를 사용하여 사용자 정보 주입
):
    """현재 로그인된 사용자의 상세 정보를 조회합니다."""
    user_data = _get_user_data_from_db(current_user["user_id"])

    if user_data:
        logger.info(f"사용자 정보 조회 성공: {current_user['user_id']}")
        return {
            "user_id": user_data["user_id"],
            "email": user_data["email"],
            "name": user_data["name"],
            "last_login": (
                user_data["last_login"].isoformat() if user_data["last_login"] else None
            ),
            "created_at": (
                user_data["created_at"].isoformat() if user_data["created_at"] else None
            ),
            "updated_at": (
                user_data["updated_at"].isoformat() if user_data["updated_at"] else None
            ),
        }
    else:
        logger.info(
            f"DB에서 사용자 정보 없음, 토큰 정보 반환: {current_user['user_id']}"
        )
        return current_user  # DB에 없는 경우, 토큰에서 얻은 기본 정보 반환


@app.get("/subscription/user/me")
async def get_current_subscription_user_info(
    current_user: dict = Depends(
        get_current_user
    ),  # Depends를 사용하여 사용자 정보 주입
):
    """현재 로그인된 사용자의 구독 관련 상세 정보를 조회합니다."""
    user_id = current_user["user_id"]

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            # 사용자 정보 조회
            cursor.execute(
                """
                SELECT user_id, email, name, last_login, created_at, updated_at
                FROM users WHERE user_id = %s
            """,
                (user_id,),
            )
            user_data = cursor.fetchone()

            # 활성 구독 정보 조회
            cursor.execute(
                """
                SELECT us.*, sp.plan_name, sp.price, sp.duration_days,
                       DATEDIFF(us.end_date, CURDATE()) as remaining_days
                FROM user_subscriptions us
                JOIN subscription_plans sp ON us.plan_id = sp.plan_id
                WHERE us.user_id = %s AND us.status = 'active'
                ORDER BY us.created_at DESC
                LIMIT 1
            """,
                (user_id,),
            )
            subscription_data = cursor.fetchone()

            # 기본 사용자 정보 구성
            if user_data:
                response = {
                    "user_id": user_data["user_id"],
                    "email": user_data["email"],
                    "name": user_data["name"],
                    "last_login": (
                        user_data["last_login"].isoformat()
                        if user_data["last_login"]
                        else None
                    ),
                    "created_at": (
                        user_data["created_at"].isoformat()
                        if user_data["created_at"]
                        else None
                    ),
                    "updated_at": (
                        user_data["updated_at"].isoformat()
                        if user_data["updated_at"]
                        else None
                    ),
                }
            else:
                response = current_user

            # 구독 정보 추가
            if subscription_data:
                response["subscription"] = {
                    "subscription_id": subscription_data["subscription_id"],
                    "plan_id": subscription_data["plan_id"],
                    "plan_name": subscription_data["plan_name"],
                    "price": subscription_data["price"],
                    "duration_days": subscription_data["duration_days"],
                    "status": subscription_data["status"],
                    "start_date": subscription_data["start_date"].isoformat(),
                    "end_date": subscription_data["end_date"].isoformat(),
                    "next_payment_date": (
                        subscription_data["next_payment_date"].isoformat()
                        if subscription_data["next_payment_date"]
                        else None
                    ),
                    "remaining_days": subscription_data["remaining_days"],
                    "customer_uid": subscription_data["customer_uid"],
                }
                logger.info(
                    f"구독 정보 조회 성공 - 사용자: {user_id}, 구독 ID: {subscription_data['subscription_id']}"
                )
            else:
                response["subscription"] = None
                logger.info(f"활성 구독 없음 - 사용자: {user_id}")

            return response

    except Exception as e:
        logger.error(f"구독 사용자 정보 조회 실패 (user_id: {user_id}): {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to retrieve subscription user information: {e}",
        )
    finally:
        if conn:
            conn.close()


@app.post("/subscription/verify-payment")
async def verify_payment(
    request: Request, authorization: str = Header(None), body: dict = Body(...)
):
    """결제 검증 및 구독 생성"""
    # 사용자 인증
    current_user = await get_current_user(request, authorization)
    user_id = current_user["user_id"]

    # 프론트엔드에서 imp_uid, plan_id, customer_uid, merchant_uid, pg_provider를 보낸다고 가정
    imp_uid = body.get("imp_uid")
    plan_id = body.get("plan_id")
    customer_uid = body.get("customer_uid")
    merchant_uid = body.get("merchant_uid")
    pg_provider = body.get("pg_provider")

    logger.info(
        f"결제 검증 시작 - 사용자: {user_id}, 플랜: {plan_id}, imp_uid: {imp_uid}"
    )

    # 실제로는 TossPayments API에 imp_uid 등으로 결제 상태를 조회해야 함
    # 아래는 예시(아임포트 V1 API 사용)
    import requests

    IMP_KEY = os.getenv("IMP_KEY", "3310784806446756")
    IMP_SECRET = os.getenv(
        "IMP_SECRET",
        "Hw6Zuz69UEbszlwdREABKjrFWKe4Pm2wEEwnraJwVRZTP1nahtKS2B1XgOyOAFfIydLn1EZG0aDcBgE8",
    )

    # 1. 아임포트 토큰 발급
    token_res = requests.post(
        "https://api.iamport.kr/users/getToken",
        json={"imp_key": IMP_KEY, "imp_secret": IMP_SECRET},
    )
    if token_res.status_code != 200:
        logger.error("아임포트 토큰 발급 실패")
        return {"status": "fail", "message": "아임포트 토큰 발급 실패"}
    access_token = token_res.json()["response"]["access_token"]

    # 2. 결제 정보 조회
    pay_res = requests.get(
        f"https://api.iamport.kr/payments/{imp_uid}",
        headers={"Authorization": access_token},
    )
    if pay_res.status_code != 200:
        logger.error("결제 정보 조회 실패")
        return {"status": "fail", "message": "결제 정보 조회 실패"}
    pay_data = pay_res.json()["response"]

    # 3. 결제 상태/금액 등 검증
    if pay_data["status"] != "paid":
        logger.error(f"결제 상태 오류: {pay_data['status']}")
        return {"status": "fail", "message": f"결제 상태: {pay_data['status']}"}

    # 4. 플랜 정보 조회
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT * FROM subscription_plans WHERE plan_id = %s AND is_active = TRUE",
                (plan_id,),
            )
            plan = cursor.fetchone()

            if not plan:
                logger.error(f"플랜을 찾을 수 없음: {plan_id}")
                return {"status": "fail", "message": "유효하지 않은 플랜입니다."}

            # 금액 검증
            if pay_data["amount"] != plan["price"]:
                logger.error(
                    f"금액 불일치 - 결제: {pay_data['amount']}, 플랜: {plan['price']}"
                )
                return {
                    "status": "fail",
                    "message": "결제 금액이 플랜 가격과 일치하지 않습니다.",
                }

            # 5. 사용자 정보 저장/업데이트
            cursor.execute(
                """
                INSERT INTO users (user_id, email, name, sub, last_login) 
                VALUES (%s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE 
                    email = VALUES(email),
                    name = VALUES(name),
                    last_login = NOW()
            """,
                (
                    user_id,
                    current_user.get("email", ""),
                    current_user.get("name", ""),
                    current_user.get("sub", ""),
                ),
            )

            # 6. 구독 정보 저장
            from datetime import datetime, timedelta

            start_date = datetime.now().date()
            end_date = start_date + timedelta(days=plan["duration_days"])

            cursor.execute(
                """
                INSERT INTO user_subscriptions 
                (user_id, plan_id, customer_uid, billing_key, status, start_date, end_date, next_payment_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    user_id,
                    plan_id,
                    customer_uid,
                    pay_data.get("billing_key", ""),
                    "active",
                    start_date,
                    end_date,
                    end_date,  # 다음 결제일은 구독 종료일
                ),
            )

            subscription_id = cursor.lastrowid

            # 7. 결제 내역 저장
            cursor.execute(
                """
                INSERT INTO payment_history 
                (user_id, subscription_id, imp_uid, merchant_uid, amount, status, payment_method)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    user_id,
                    subscription_id,
                    imp_uid,
                    merchant_uid,
                    pay_data["amount"],
                    "success",
                    pay_data.get("pay_method", "card"),
                ),
            )

            conn.commit()
            logger.info(
                f"구독 생성 성공 - 사용자: {user_id}, 구독 ID: {subscription_id}"
            )

            return {
                "status": "success",
                "message": "구독이 성공적으로 생성되었습니다.",
                "subscription_id": subscription_id,
                "data": {
                    "plan_name": plan["plan_name"],
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "amount": pay_data["amount"],
                },
            }

    except Exception as e:
        logger.error(f"구독 생성 중 오류 발생: {e}")
        if conn:
            conn.rollback()
        return {"status": "fail", "message": f"구독 생성 실패: {str(e)}"}
    finally:
        if conn:
            conn.close()
