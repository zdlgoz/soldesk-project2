from fastapi import FastAPI, HTTPException, Depends, Header
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

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Portone Subscription API", version="1.0.0")

# CORS 설정 - S3 도메인 허용
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://your-subscription-frontend.s3-website.ap-northeast-2.amazonaws.com",
        "https://your-subscription-frontend.s3-website.ap-northeast-2.amazonaws.com",
        "http://localhost:3000",  # 개발용
        "http://localhost:8080",  # 개발용
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 환경 변수 설정 (포트원, RDS, Cognito)
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

# Cognito 설정
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID", "ap-northeast-2_xxxxxxxxx")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID", "your-client-id")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET", "your-client-secret")
COGNITO_DOMAIN = os.getenv(
    "COGNITO_DOMAIN", "your-domain.auth.ap-northeast-2.amazoncognito.com"
)
AWS_REGION = os.getenv("AWS_REGION", "ap-northeast-2")

# AWS 클라이언트
cognito_client = boto3.client("cognito-idp", region_name=AWS_REGION)


# JWT 토큰 검증을 위한 Cognito 공개키 가져오기
def get_cognito_public_keys():
    """Cognito User Pool의 공개키들을 가져옵니다."""
    try:
        response = requests.get(
            f"https://cognito-idp.{AWS_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}/.well-known/jwks.json"
        )
        response.raise_for_status()
        return response.json()["keys"]
    except Exception as e:
        logger.error(f"Cognito 공개키 가져오기 실패: {e}")
        return None


# JWT 토큰 검증
def verify_jwt_token(token: str):
    """JWT 토큰을 검증하고 페이로드를 반환합니다."""
    try:
        # 토큰 헤더에서 kid (Key ID) 추출
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")

        if not kid:
            raise HTTPException(status_code=401, detail="Invalid token header")

        # Cognito 공개키 가져오기
        public_keys = get_cognito_public_keys()
        if not public_keys:
            raise HTTPException(status_code=500, detail="Failed to get public keys")

        # 해당 kid의 공개키 찾기
        public_key = None
        for key in public_keys:
            if key["kid"] == kid:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
                break

        if not public_key:
            raise HTTPException(status_code=401, detail="Invalid token key")

        # 토큰 검증
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


# 현재 사용자 가져오기 (토큰에서)
async def get_current_user(authorization: Optional[str] = Header(None)):
    """Authorization 헤더에서 토큰을 추출하고 현재 사용자 정보를 반환합니다."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    try:
        # Bearer 토큰 추출
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401, detail="Invalid authorization header format"
            )

        token = authorization.split(" ")[1]
        payload = verify_jwt_token(token)

        return {
            "user_id": payload.get("cognito:username") or payload.get("sub"),
            "sub": payload.get("sub"),
            "email": payload.get("email"),
            "name": payload.get("name") or payload.get("cognito:username"),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"사용자 정보 추출 실패: {e}")
        raise HTTPException(
            status_code=401, detail="Failed to extract user information"
        )


# ------------------- 데이터 모델 정의 -------------------
from pydantic import BaseModel
from typing import Optional, List


class PaymentVerification(BaseModel):
    imp_uid: str
    plan_id: str
    customer_uid: str
    merchant_uid: str
    pg_provider: str = "tosspayments"


class CancellationRequest(BaseModel):
    subscription_id: int
    cancel_reason: Optional[str] = None


# ------------------- 헬스체크 및 루트 엔드포인트 -------------------
@app.get("/health")
async def health_check():
    """헬스체크 엔드포인트"""
    try:
        # DB 연결 테스트
        conn = get_db()
        conn.close()
        return {"status": "healthy", "timestamp": datetime.now().isoformat()}
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unhealthy")


@app.get("/")
async def root():
    """루트 엔드포인트"""
    return {"message": "Portone Subscription API", "version": "1.0.0"}


# ------------------- DB 연결 함수 -------------------
def get_db():
    """RDS(MySQL) DB 연결 반환"""
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
        logger.error(f"Database connection failed: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")


# ------------------- 포트원 액세스 토큰 -------------------
def get_access_token():
    """포트원 API 액세스 토큰 발급"""
    try:
        url = "https://api.iamport.kr/users/getToken"
        payload = {"imp_key": IMP_KEY, "imp_secret": IMP_SECRET}
        res = requests.post(url, json=payload, timeout=10)
        res.raise_for_status()
        return res.json()["response"]["access_token"]
    except Exception as e:
        logger.error(f"Failed to get access token: {e}")
        raise HTTPException(status_code=500, detail="Failed to get access token")


# ------------------- Cognito 토큰 교환 엔드포인트 -------------------
@app.post("/auth/token")
async def exchange_code_for_token(code: str, redirect_uri: str):
    """Authorization Code를 Access Token으로 교환합니다."""
    try:
        # Cognito 토큰 엔드포인트 호출
        token_url = f"https://{COGNITO_DOMAIN}/oauth2/token"

        data = {
            "grant_type": "authorization_code",
            "client_id": COGNITO_CLIENT_ID,
            "code": code,
            "redirect_uri": redirect_uri,
        }

        # Client Secret이 있는 경우 추가
        if COGNITO_CLIENT_SECRET:
            data["client_secret"] = COGNITO_CLIENT_SECRET

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        response = requests.post(token_url, data=data, headers=headers)
        response.raise_for_status()

        token_data = response.json()

        # 사용자 정보를 MySQL에 저장/업데이트
        if "id_token" in token_data:
            id_payload = verify_jwt_token(token_data["id_token"])
            user_id = id_payload.get("cognito:username") or id_payload.get("sub")

            # 사용자 정보 저장
            conn = get_db()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO users (user_id, email, name, sub, last_login, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        email = VALUES(email),
                        name = VALUES(name),
                        last_login = VALUES(last_login),
                        updated_at = VALUES(updated_at)
                    """,
                        (
                            user_id,
                            id_payload.get("email"),
                            id_payload.get("name") or user_id,
                            id_payload.get("sub"),
                            datetime.now(),
                            datetime.now(),
                        ),
                    )
            finally:
                conn.close()

        return {
            "access_token": token_data.get("access_token"),
            "id_token": token_data.get("id_token"),
            "refresh_token": token_data.get("refresh_token"),
            "expires_in": token_data.get("expires_in"),
            "token_type": token_data.get("token_type"),
        }

    except requests.exceptions.RequestException as e:
        logger.error(f"토큰 교환 요청 실패: {e}")
        raise HTTPException(status_code=400, detail="Failed to exchange code for token")
    except Exception as e:
        logger.error(f"토큰 교환 실패: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ------------------- 현재 사용자 정보 엔드포인트 -------------------
@app.get("/user/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """현재 로그인된 사용자의 정보를 반환합니다."""
    try:
        # MySQL에서 사용자 정보 가져오기
        conn = get_db()
        try:
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
                    # MySQL에 없는 경우 토큰 정보 반환
                    return current_user
        finally:
            conn.close()

    except Exception as e:
        logger.error(f"사용자 정보 조회 실패: {e}")
        raise HTTPException(status_code=500, detail="Failed to get user information")


# ------------------- 구독 플랜 목록 조회 -------------------
@app.get("/subscription/plans")
async def get_subscription_plans():
    """구독 플랜 전체 목록 조회 API"""
    try:
        conn = get_db()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM subscription_plans WHERE is_active = TRUE")
            plans = cursor.fetchall()
        return {"plans": plans}
    except Exception as e:
        logger.error(f"Failed to get subscription plans: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        if "conn" in locals():
            conn.close()


# ------------------- 사용자 구독 정보 조회 -------------------
@app.get("/subscription/user/me")
async def get_user_subscription(current_user: dict = Depends(get_current_user)):
    """현재 로그인한 사용자의 구독 정보 조회 API"""
    try:
        conn = get_db()
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT us.*, sp.plan_name, sp.price
                FROM user_subscriptions us
                JOIN subscription_plans sp ON us.plan_id = sp.plan_id
                WHERE us.user_id = %s AND us.status = 'active'
                ORDER BY us.created_at DESC
                LIMIT 1
            """,
                (current_user["user_id"],),
            )
            subscription = cursor.fetchone()
            if subscription:
                # 남은 일수 계산
                remaining_days = (subscription["end_date"] - datetime.now().date()).days
                subscription["remaining_days"] = max(0, remaining_days)
        return {"subscription": subscription}
    except Exception as e:
        logger.error(f"Failed to get user subscription: {e}")
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    finally:
        if "conn" in locals():
            conn.close()


# ------------------- 결제 검증 및 구독 생성 -------------------
@app.post("/subscription/verify-payment")
async def verify_subscription_payment(
    data: PaymentVerification, current_user: dict = Depends(get_current_user)
):
    """결제 성공 후 구독 생성 및 결제 내역 저장 API"""
    try:
        # 1. 포트원 결제 정보 조회
        access_token = get_access_token()
        url = f"https://api.iamport.kr/payments/{data.imp_uid}"
        headers = {"Authorization": access_token}
        res = requests.get(url, headers=headers, timeout=10)
        res.raise_for_status()
        payment_data = res.json()["response"]

        conn = get_db()
        with conn.cursor() as cursor:
            # 2. 구독 플랜 정보 조회
            cursor.execute(
                "SELECT * FROM subscription_plans WHERE plan_id = %s", (data.plan_id,)
            )
            plan = cursor.fetchone()
            if not plan:
                raise HTTPException(
                    status_code=404, detail="Subscription plan not found"
                )

            # 3. 기존 활성 구독 취소 처리
            cursor.execute(
                """
                SELECT subscription_id FROM user_subscriptions 
                WHERE user_id = %s AND status = 'active'
            """,
                (current_user["user_id"],),
            )
            existing_subscription = cursor.fetchone()
            if existing_subscription:
                cursor.execute(
                    """
                    UPDATE user_subscriptions 
                    SET status = 'cancelled', updated_at = NOW()
                    WHERE subscription_id = %s
                """,
                    (existing_subscription["subscription_id"],),
                )

            # 4. 새 구독 생성
            start_date = datetime.now().date()
            end_date = start_date + timedelta(days=plan["duration_days"])
            next_payment_date = end_date

            cursor.execute(
                """
                INSERT INTO user_subscriptions 
                (user_id, plan_id, customer_uid, billing_key, status, start_date, end_date, next_payment_date)
                VALUES (%s, %s, %s, %s, 'active', %s, %s, %s)
            """,
                (
                    current_user["user_id"],
                    data.plan_id,
                    data.customer_uid,
                    payment_data.get("billing_key"),
                    start_date,
                    end_date,
                    next_payment_date,
                ),
            )

            # 5. 결제 내역 저장
            cursor.execute(
                """
                INSERT INTO payment_history 
                (user_id, subscription_id, imp_uid, merchant_uid, amount, status, payment_method, created_at)
                VALUES (%s, LAST_INSERT_ID(), %s, %s, %s, 'success', %s, NOW())
            """,
                (
                    current_user["user_id"],
                    data.imp_uid,
                    payment_data.get("merchant_uid"),
                    payment_data.get("amount"),
                    payment_data.get("pay_method"),
                ),
            )

            logger.info(
                f"Subscription created successfully for user: {current_user['user_id']}"
            )
            return {"message": "Subscription created successfully", "status": "success"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to verify payment: {e}")
        raise HTTPException(status_code=500, detail=f"Payment verification failed: {e}")
    finally:
        if "conn" in locals():
            conn.close()


# ------------------- 구독 취소 -------------------
@app.post("/subscription/cancel")
async def cancel_subscription(
    data: CancellationRequest, current_user: dict = Depends(get_current_user)
):
    """구독 취소 API"""
    try:
        conn = get_db()
        with conn.cursor() as cursor:
            # 구독 정보 확인
            cursor.execute(
                """
                SELECT * FROM user_subscriptions 
                WHERE subscription_id = %s AND user_id = %s AND status = 'active'
            """,
                (data.subscription_id, current_user["user_id"]),
            )
            subscription = cursor.fetchone()
            if not subscription:
                raise HTTPException(
                    status_code=404, detail="Active subscription not found"
                )

            # 포트원에서 정기결제 취소
            try:
                access_token = get_access_token()
                url = f"https://api.iamport.kr/subscribe/payments/unschedule"
                headers = {"Authorization": access_token}
                payload = {"customer_uid": subscription["customer_uid"]}
                res = requests.post(url, json=payload, headers=headers, timeout=10)
                res.raise_for_status()
            except Exception as e:
                logger.warning(f"Failed to cancel subscription in Portone: {e}")

            # DB에서 구독 상태 업데이트
            cursor.execute(
                """
                UPDATE user_subscriptions 
                SET status = 'cancelled', cancel_reason = %s, updated_at = NOW()
                WHERE subscription_id = %s
            """,
                (data.cancel_reason, data.subscription_id),
            )

            logger.info(f"Subscription cancelled successfully: {data.subscription_id}")
            return {"message": "Subscription cancelled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel subscription: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to cancel subscription: {e}"
        )
    finally:
        if "conn" in locals():
            conn.close()


# ------------------- 정기결제 처리 -------------------
@app.post("/subscription/process-recurring-payments")
async def process_recurring_payments():
    """정기결제 처리 API (스케줄러에서 호출)"""
    try:
        conn = get_db()
        with conn.cursor() as cursor:
            # 만료 예정인 구독 조회 (3일 전)
            cursor.execute(
                """
                SELECT us.*, sp.price 
                FROM user_subscriptions us
                JOIN subscription_plans sp ON us.plan_id = sp.plan_id
                WHERE us.status = 'active' 
                AND us.next_payment_date <= DATE_ADD(CURDATE(), INTERVAL 3 DAY)
            """
            )
            expiring_subscriptions = cursor.fetchall()

            for subscription in expiring_subscriptions:
                try:
                    # 포트원에서 정기결제 실행
                    access_token = get_access_token()
                    url = "https://api.iamport.kr/subscribe/payments/onetime"
                    headers = {"Authorization": access_token}
                    payload = {
                        "customer_uid": subscription["customer_uid"],
                        "merchant_uid": f"recurring_{subscription['subscription_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                        "amount": subscription["price"],
                        "name": f"{subscription['plan_id']} 구독 갱신",
                    }
                    res = requests.post(url, json=payload, headers=headers, timeout=10)
                    res.raise_for_status()
                    payment_data = res.json()["response"]

                    if payment_data["status"] == "paid":
                        # 구독 기간 연장
                        new_end_date = subscription["end_date"] + timedelta(days=30)
                        new_next_payment_date = new_end_date

                        cursor.execute(
                            """
                            UPDATE user_subscriptions 
                            SET end_date = %s, next_payment_date = %s, updated_at = NOW()
                            WHERE subscription_id = %s
                        """,
                            (
                                new_end_date,
                                new_next_payment_date,
                                subscription["subscription_id"],
                            ),
                        )

                        # 결제 내역 저장
                        cursor.execute(
                            """
                            INSERT INTO payment_history 
                            (user_id, subscription_id, imp_uid, merchant_uid, amount, status, payment_method, created_at)
                            VALUES (%s, %s, %s, %s, %s, 'success', 'card', NOW())
                        """,
                            (
                                subscription["user_id"],
                                subscription["subscription_id"],
                                payment_data["imp_uid"],
                                payment_data["merchant_uid"],
                                payment_data["amount"],
                            ),
                        )

                        logger.info(
                            f"Recurring payment successful for subscription: {subscription['subscription_id']}"
                        )
                    else:
                        # 결제 실패 시 구독 상태 변경
                        cursor.execute(
                            """
                            UPDATE user_subscriptions 
                            SET status = 'payment_failed', updated_at = NOW()
                            WHERE subscription_id = %s
                        """,
                            (subscription["subscription_id"],),
                        )
                        logger.warning(
                            f"Recurring payment failed for subscription: {subscription['subscription_id']}"
                        )

                except Exception as e:
                    logger.error(
                        f"Failed to process recurring payment for subscription {subscription['subscription_id']}: {e}"
                    )
                    continue

            return {
                "message": "Recurring payments processed",
                "processed_count": len(expiring_subscriptions),
            }

    except Exception as e:
        logger.error(f"Failed to process recurring payments: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to process recurring payments: {e}"
        )
    finally:
        if "conn" in locals():
            conn.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
