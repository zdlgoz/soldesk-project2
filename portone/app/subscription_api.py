from fastapi import FastAPI, HTTPException, Header, Request, Depends
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
    allow_credentials=True, # 인증 필요시 True
    allow_methods=["*"],    # 모든 HTTP 메서드 허용
    allow_headers=["*"],    # 모든 헤더 허용
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

COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID", "ap-northeast-2_xxxxxxxxx") # 실제 User Pool ID로 변경 필요
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID", "your-client-id") # 실제 Client ID로 변경 필요
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET", "your-client-secret") # 실제 Client Secret으로 변경 필요
COGNITO_DOMAIN = os.getenv(
    "COGNITO_DOMAIN", "your-domain.auth.ap-northeast-2.amazoncognito.com" # 실제 Cognito 도메인으로 변경 필요
)
AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-2")

cognito_client = boto3.client("cognito-idp", region_name=AWS_REGION)

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
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            logger.warning("토큰 헤더에 'kid'가 없습니다.")
            raise HTTPException(status_code=401, detail="Invalid token header: Missing 'kid'")

        public_keys = get_cognito_public_keys()
        if not public_keys:
            logger.error("공개키를 가져오지 못했습니다.")
            raise HTTPException(status_code=500, detail="Failed to get public keys for token verification")

        public_key = None
        for key in public_keys:
            if key["kid"] == kid:
                public_key = RSAAlgorithm.from_jwk(json.dumps(key))
                break

        if not public_key:
            logger.warning(f"토큰의 'kid'({kid})에 해당하는 공개키를 찾을 수 없습니다.")
            raise HTTPException(status_code=401, detail="Invalid token key: No matching public key found")

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            issuer=f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}",
        )
        logger.info("JWT 토큰 검증 성공")
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("토큰 만료: ExpiredSignatureError")
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        logger.warning(f"유효하지 않은 토큰: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"토큰 검증 중 예상치 못한 오류 발생: {e}")
        raise HTTPException(status_code=401, detail="Token verification failed due to an unexpected error")


async def get_current_user(
    request: Request, authorization: Optional[str] = Header(None)
):
    """요청 헤더에서 JWT 토큰을 추출하고 현재 사용자 정보를 반환합니다."""
    if not authorization or not authorization.startswith("Bearer "):
        logger.warning("Authorization 헤더가 없거나 형식이 잘못되었습니다.")
        raise HTTPException(
            status_code=401, detail="Invalid or missing Authorization header. Expected 'Bearer <token>'"
        )

    token = authorization.split(" ")[1]
    payload = verify_jwt_token(token)
    
    user_id = payload.get("cognito:username") or payload.get("sub")
    if not user_id:
        logger.error("토큰 페이로드에서 사용자 ID를 찾을 수 없습니다.")
        raise HTTPException(status_code=500, detail="Could not retrieve user ID from token payload.")

    return {
        "user_id": user_id,
        "sub": payload.get("sub"),
        "email": payload.get("email"),
        "name": payload.get("name") or payload.get("cognito:username"),
    }

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
        raise HTTPException(status_code=500, detail=f"Failed to retrieve user information from database: {e}")
    finally:
        if conn:
            conn.close()


@app.get("/subscription/plans")
async def get_subscription_plans():
    """활성화된 구독 플랜 목록을 조회합니다."""
    conn = None
    try:
        conn = get_db_connection() # 올바른 연결 사용
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM subscription_plans WHERE is_active = TRUE")
            plans = cursor.fetchall()
        logger.info("구독 플랜 조회 성공")
        return {"plans": plans}
    except Exception as e:
        logger.error(f"구독 플랜 조회 실패: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get subscription plans: {e}")
    finally:
        if conn:
            conn.close()


@app.get("/user/me")
async def get_current_user_info(
    current_user: dict = Depends(get_current_user) # Depends를 사용하여 사용자 정보 주입
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
        logger.info(f"DB에서 사용자 정보 없음, 토큰 정보 반환: {current_user['user_id']}")
        return current_user # DB에 없는 경우, 토큰에서 얻은 기본 정보 반환


@app.get("/subscription/user/me")
async def get_current_subscription_user_info(
    current_user: dict = Depends(get_current_user) # Depends를 사용하여 사용자 정보 주입
):
    """현재 로그인된 사용자의 구독 관련 상세 정보를 조회합니다. (현재는 /user/me와 동일)"""
    # 이 엔드포인트는 /user/me와 동일한 로직을 사용하므로,
    # 필요에 따라 구독 관련 추가 정보를 조회하도록 확장할 수 있습니다.
    user_data = _get_user_data_from_db(current_user["user_id"])
    
    if user_data:
        logger.info(f"구독 사용자 정보 조회 성공: {current_user['user_id']}")
        return {
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
        logger.info(f"DB에서 구독 사용자 정보 없음, 토큰 정보 반환: {current_user['user_id']}")
        return current_user # DB에 없는 경우, 토큰에서 얻은 기본 정보 반환

