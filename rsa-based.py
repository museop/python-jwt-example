import jwt
from cryptography.hazmat.primitives import serialization

######### JWT 발행 서비스 ##########

# 개인 키 파일 읽기
with open("private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=b"your_password_here",  # 비밀 키 암호가 설정된 경우 입력
        backend=None,
    )

payload = {"sub": "1234567890", "name": "John Doe", "admin": True}

# 개인 키를 사용하여 JWT 생성
token = jwt.encode(payload, private_key, algorithm="RS256")
print(f"JWT Token: {token}")

######### JWT 검증 서비스 ##########

# 공개 키 파일 읽기
with open("public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read(), backend=None)

# 토큰 검증
try:
    decoded = jwt.decode(token, public_key, algorithms=["RS256"])
    print(f"Decoded Payload: {decoded}")
except jwt.ExpiredSignatureError:
    print("토큰이 만료되었습니다.")
except jwt.InvalidTokenError:
    print("유효하지 않은 토큰입니다.")
