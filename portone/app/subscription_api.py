from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import requests
import jwt
import json
import os
from datetime import datetime, timedelta
import boto3
from typing import Optional
import logging
import pymysql
from pymysql.cursors import DictCursor
from fastapi.responses import JSONResponse, Response
from functools import lru_cache

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Portone Subscription API", version="1.0.0")

origins = [
    "https://www.highlight.monster",
    "https://api.highlight.monster",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # 명확한 도메인만 허용
    allow_credentials=True, # 인증 필요시 True
    allow_methods=["*"],
    allow_headers=["*"],
)

# 환경 변수 설정
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

COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID", "ap-northeast-2_xxxxxxxxx")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID", "your-client-id")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET", "your-client-secret")
COGNITO_DOMAIN = os.getenv(
    "COGNITO_DOMAIN", "your-domain.auth.ap-northeast-2.amazoncognito.com"
)
AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-2")

cognito_client = boto3.client("cognito-idp", region_name=AWS_REGION)


def get_db_connection():
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
        return conn
    except Exception as e:
        logger.error(f"DB 연결 실패: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")

@lru_cache(maxsize=1)
def get_cognito_public_keys_cached():
    try:
        response = requests.get(
            f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
        )
        response.raise_for_status()
        return response.json()["keys"]
    except Exception as e:
        logger.error(f"Cognito 공개키 가져오기 실패: {e}")
        return None

def get_cognito_public_keys():
    return get_cognito_public_keys_cached()

def verify_jwt_token(token: str):
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Invalid token header")

        public_keys = get_cognito_public_keys()
        if not public_keys:
            raise HTTPException(status_code=500, detail="Failed to get public keys")

        public_key = None
        for key in public_keys:
            if key["kid"] == kid:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                break

        if not public_key:
            raise HTTPException(status_code=401, detail="Invalid token key")

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=COGNITO_CLIENT_ID,
            issuer=f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}",
        )

        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error(f"토큰 검증 실패: {e}")
        raise HTTPException(status_code=401, detail="Token verification failed")


async def get_current_user(
    request: Request, authorization: Optional[str] = Header(None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401, detail="Invalid or missing Authorization header"
        )

    token = authorization.split(" ")[1]
    payload = verify_jwt_token(token)
    return {
        "user_id": payload.get("cognito:username") or payload.get("sub"),
        "sub": payload.get("sub"),
        "email": payload.get("email"),
        "name": payload.get("name") or payload.get("cognito:username"),
    }


@app.get("/subscription/plans")
async def get_subscription_plans():
    try:
        conn = get_db_connection()
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
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM subscription_plans WHERE is_active = TRUE")
            plans = cursor.fetchall()
        return {"plans": plans}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Failed to get subscription plans: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        if "conn" in locals():
            conn.close()


@app.get("/user/me")
async def get_current_user_info(
    request: Request, authorization: Optional[str] = Header(None)
):
    current_user = await get_current_user(request, authorization)
    try:
        conn = get_db_connection()
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
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id, email, name, last_login, created_at, updated_at
                FROM users WHERE user_id = %s
                """,
                (current_user["user_id"],),
            )
            user_data = cursor.fetchone()
            if user_data:
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
                return current_user
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"사용자 정보 조회 실패: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get user information: {e}")
    finally:
        if "conn" in locals():
            conn.close()


@app.get("/subscription/user/me")
async def get_current_subscription_user_info(
    request: Request, authorization: Optional[str] = Header(None)
):
    current_user = await get_current_user(request, authorization)
    try:
        conn = get_db_connection()
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
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT user_id, email, name, last_login, created_at, updated_at
                FROM users WHERE user_id = %s
                """,
                (current_user["user_id"],),
            )
            user_data = cursor.fetchone()
            if user_data:
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
                return current_user
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"사용자 정보 조회 실패: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get user information: {e}")
    finally:
        if "conn" in locals():
            conn.close()


@app.options("/{rest_of_path:path}")
async def preflight_handler(rest_of_path: str):
    return Response(status_code=200)

