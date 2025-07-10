import os
import json
import boto3
import time
import logging
from solapi.services.message_service import SolapiMessageService
from solapi.model.request.message import Message

# 로깅 설정
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# AWS 서비스 클라이언트 초기화
sqs_client = boto3.client("sqs", region_name=os.getenv("AWS_REGION", "ap-northeast-2"))
secretsmanager_client = boto3.client(
    "secretsmanager", region_name=os.getenv("AWS_REGION", "ap-northeast-2")
)

# 환경 변수에서 SQS 큐 URL 및 Secrets Manager 시크릿 이름 가져오기
SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")
SOLAPI_SECRET_NAME = os.getenv("SOLAPI_SECRET_NAME")


# 환경 변수 검증 함수
def validate_environment_variables():
    """필수 환경 변수가 설정되어 있는지 검증"""
    required_vars = {
        "SQS_QUEUE_URL": SQS_QUEUE_URL,
        "SOLAPI_SECRET_NAME": SOLAPI_SECRET_NAME,
    }

    missing_vars = [var for var, value in required_vars.items() if not value]

    if missing_vars:
        logger.error(f"Missing required environment variables: {missing_vars}")
        return False

    # SQS 큐 URL 형식 검증
    if SQS_QUEUE_URL and not SQS_QUEUE_URL.startswith("https://sqs."):
        logger.error(f"Invalid SQS queue URL format: {SQS_QUEUE_URL}")
        return False

    return True


# 전화번호 형식 검증 함수
def validate_phone_number(phone_number):
    """전화번호 형식 검증"""
    if not phone_number:
        return False

    # 숫자만 추출
    digits_only = "".join(filter(str.isdigit, phone_number))

    # 010으로 시작하는 11자리 번호인지 확인
    if len(digits_only) == 11 and digits_only.startswith("010"):
        return True
    else:
        logger.warning(f"Invalid phone number format: {phone_number}")
        return False


# Solapi API 키 및 시크릿 로드 함수
def get_solapi_credentials(secret_name):
    try:
        get_secret_value_response = secretsmanager_client.get_secret_value(
            SecretId=secret_name
        )
        if "SecretString" in get_secret_value_response:
            secret = json.loads(get_secret_value_response["SecretString"])
            required_keys = ["api_key", "api_secret", "from_number"]

            # 필수 키 검증
            missing_keys = [key for key in required_keys if key not in secret]
            if missing_keys:
                raise ValueError(f"Missing required keys in secret: {missing_keys}")

            return (
                secret["api_key"],
                secret["api_secret"],
                secret["from_number"],
            )
        else:
            raise ValueError("Secret is not a string")
    except Exception as e:
        logger.error(f"Error retrieving secret '{secret_name}': {e}")
        raise


# SMS 발송 로직
def send_sms(to_number, message_content, solapi_key, solapi_secret, from_number):
    try:
        # 전화번호 형식 검증
        if not validate_phone_number(to_number):
            logger.error(f"Invalid phone number format: {to_number}")
            return False

        message_service = SolapiMessageService(solapi_key, solapi_secret)
        message = Message(to=to_number, from_=from_number, text=message_content)
        response = message_service.send(message)
        logger.info(f"SMS 발송 성공: {to_number} - {response}")
        return True
    except Exception as e:
        logger.error(f"SMS 발송 실패: {e}")
        return False


# 메인 워커 로직
def main_worker():
    # 환경 변수 검증
    if not validate_environment_variables():
        logger.error("Environment validation failed. Exiting.")
        return

    # Solapi 자격 증명 미리 로드 (워커 시작 시 한 번만 로드)
    try:
        solapi_key, solapi_secret, from_number = get_solapi_credentials(
            SOLAPI_SECRET_NAME
        )
        logger.info("Solapi credentials loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load Solapi credentials, exiting: {e}")
        return

    logger.info(f"SMS Sender Worker Started, polling SQS queue: {SQS_QUEUE_URL}")

    while True:
        try:
            # SQS에서 메시지 가져오기 (Long Polling 사용)
            response = sqs_client.receive_message(
                QueueUrl=SQS_QUEUE_URL,
                MaxNumberOfMessages=10,  # 한 번에 최대 10개 메시지 가져오기
                WaitTimeSeconds=20,  # 20초 동안 메시지 대기 (Long Polling)
            )

            messages = response.get("Messages", [])
            if not messages:
                logger.debug("No messages in queue, waiting...")
                time.sleep(5)  # 메시지가 없을 때 잠시 대기
                continue

            logger.info(f"Processing {len(messages)} messages")

            for message in messages:
                try:
                    body = json.loads(message["Body"])
                    phone_number = body.get("phone_number")
                    message_content = body.get("message_content")

                    if phone_number and message_content:
                        logger.info(f"Processing message for {phone_number}...")
                        success = send_sms(
                            phone_number,
                            message_content,
                            solapi_key,
                            solapi_secret,
                            from_number,
                        )
                        if success:
                            # SMS 발송 성공 시 SQS 메시지 삭제
                            sqs_client.delete_message(
                                QueueUrl=SQS_QUEUE_URL,
                                ReceiptHandle=message["ReceiptHandle"],
                            )
                            logger.info(f"Message deleted from SQS for {phone_number}")
                        else:
                            logger.warning(
                                f"Failed to send SMS for {phone_number}. Message will be visible again after visibility timeout."
                            )
                    else:
                        logger.warning(
                            f"Invalid message format in SQS: {body}. Deleting message to avoid reprocessing."
                        )
                        sqs_client.delete_message(
                            QueueUrl=SQS_QUEUE_URL,
                            ReceiptHandle=message["ReceiptHandle"],
                        )

                except json.JSONDecodeError:
                    logger.error(
                        f"Invalid JSON in message body: {message['Body']}. Deleting message."
                    )
                    sqs_client.delete_message(
                        QueueUrl=SQS_QUEUE_URL, ReceiptHandle=message["ReceiptHandle"]
                    )
                except KeyError as ke:
                    logger.error(f"Missing key in SQS message: {ke}. Deleting message.")
                    sqs_client.delete_message(
                        QueueUrl=SQS_QUEUE_URL, ReceiptHandle=message["ReceiptHandle"]
                    )
                except Exception as e:
                    logger.error(
                        f"Error processing SQS message: {e}. Message will be visible again after visibility timeout."
                    )

        except Exception as e:
            logger.error(f"Error receiving messages from SQS: {e}")
            time.sleep(10)  # 오류 발생 시 잠시 대기 후 재시도


if __name__ == "__main__":
    main_worker()
