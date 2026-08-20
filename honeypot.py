import asyncio
import json
from datetime import datetime

# 로그가 저장될 파일명
LOG_FILE = "honeypot_log.json"

async def handle_client(reader, writer):
    # 1. 접속한 클라이언트(공격자)의 IP 및 포트 정보 추출
    peername = writer.get_extra_info('peername')
    src_ip, src_port = peername[0], peername[1]
    
    # 2. 타겟이 된 허니팟 포트 정보 추출
    sockname = writer.get_extra_info('sockname')
    dest_port = sockname[1]

    print(f"[탐지] 연결됨: {src_ip}:{src_port} -> 포트 {dest_port}")

    payload = ""
    try:
        # 3. 공격자가 전송하는 데이터(페이로드) 수신 (타임아웃 5초 설정)
        data = await asyncio.wait_for(reader.read(1024), timeout=5.0)
        payload = data.decode('utf-8', errors='ignore').strip()
    except asyncio.TimeoutError:
        payload = "TIMEOUT_NO_DATA"
    except Exception as e:
        payload = f"ERROR: {str(e)}"

    # 4. Wazuh 연동 및 분석에 용이한 JSON 구조체 생성
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "protocol": "TCP",
        "payload": payload
    }

    # 5. 로컬 파일에 JSON 로그 한 줄씩 추가 (Append 모드)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        print(f"[기록 완료] 로그가 {LOG_FILE}에 저장되었습니다.")
    except Exception as e:
        print(f"[오류] 파일 쓰기 실패: {e}")

    # 6. 공격자 속이기 위한 가짜 배너(SSH 응답) 전송 후 연결 종료
    writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
    await writer.drain()
    writer.close()
    await writer.wait_closed()

async def main():
    # 로컬 테스트를 위해 127.0.0.1과 2222번 포트 사용
    server = await asyncio.start_server(handle_client, '127.0.0.1', 2222)
    print(f"[*] 허니팟 서버 구동 중: 127.0.0.1:2222")

    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(main())