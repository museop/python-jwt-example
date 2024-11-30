import jwt
import datetime

# 대칭 키 방식(HMAC)

# 비밀 키
SECRET_KEY = "your_secret_key"

# JWT 생성
# 표준 클레임 (iss, exp, sub)
# iss (발행자): 토큰을 발행한 주체 확인
# sub (주체): 토큰의 대상(사용자) 식별
# exp (만료 시간): 토큰이 언제 만료되는지 명시
# iat (발행 시각): 토큰 발행 시간 기록
# aud (수신 대상): 토큰의 예상 수신자 확인

payload = {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": datetime.datetime.now(datetime.UTC),
    "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=30),
}

token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
print(f"JWT Token: {token}")

# JWT 검증
try:
    decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    print(f"Decoded Payload: {decoded}")
except jwt.ExpiredSignatureError:
    print("토큰이 만료되었습니다.")
except jwt.InvalidTokenError:
    print("유효하지 않은 토큰입니다.")
