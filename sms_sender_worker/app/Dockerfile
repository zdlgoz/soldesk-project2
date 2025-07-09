# 파이썬 공식 이미지 사용 (3.11 버전)
FROM python:3.11-slim-buster

# 작업 디렉토리 설정
WORKDIR /app

# 필요한 패키지 설치 및 캐시 정리
# build-essential은 pip install 과정에서 필요한 컴파일러 등을 제공합니다.
RUN apt-get update && apt-get install -y --no-install-recommends \
    #build-essential \
    && rm -rf /var/lib/apt/lists/*

# 파이썬 의존성 파일 복사 및 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 실행을 위한 비-루트 사용자 생성
RUN adduser --system --group appuser

# 애플리케이션 코드 복사
COPY sms_sender_worker.py .

# 비-루트 사용자로 전환
USER appuser

# 컨테이너 실행 시 명령 정의
# 환경 변수는 Kubernetes Deployment에서 주입
CMD ["python", "sms_sender_worker.py"]