import json
import base64
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# 헤더와 페이로드 JSON 생성
header = {"alg": "RS256", "typ": "JWT"}
payload = {"sub": "1234567890", "name": "John Doe", "admin": True}


# Base64 URL 인코딩 함수 정의
def base64_url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


# 헤더와 페이로드를 Base64 URL 인코딩
encoded_header = base64_url_encode(json.dumps(header).encode("utf-8"))
encoded_payload = base64_url_encode(json.dumps(payload).encode("utf-8"))

# 메시지 생성 (헤더.페이로드)
message = f"{encoded_header}.{encoded_payload}"

# RSA 개인 키 파일에서 개인 키 로드
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=b"your_password_here",  # 비밀 키 암호 입력 (비밀번호가 있을 경우)
        backend=None,
    )

# 메시지에 서명 생성 (RS256 사용)
signature = private_key.sign(
    message.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
)

# 서명을 Base64 URL 인코딩
encoded_signature = base64_url_encode(signature)

# 최종 JWT 토큰 생성 (헤더.페이로드.서명)
jwt_token = f"{message}.{encoded_signature}"

print(f"Generated JWT Token: {jwt_token}")
