import pandas as pd
import psycopg2

# CSV 로드
df = pd.read_csv("C:\\Users\\aromi\\바탕 화면\\lang_flow\\RECmd_Batch_DFIRBatch_Output_tagged.csv", encoding='utf-8')

# DB 연결
conn = psycopg2.connect(
    dbname="rudrb",
    user="rudrb",
    password="rudrb123",
    host="localhost",
    port="5432"
)
cur = conn.cursor()

# 테이블별 생성 및 삽입
for tag in df['tag'].dropna().unique():
    table_name = tag.strip().lower()
    tag_df = df[df['tag'] == tag]

    # 컬럼명 정제
    tag_df.columns = [c.lower() for c in tag_df.columns]

    # 테이블 생성 (없으면)
    cols = ", ".join([f"{c} TEXT" for c in tag_df.columns])
    cur.execute(f'CREATE TABLE IF NOT EXISTS "{table_name}" ({cols});')

    # 데이터 삽입
    for _, row in tag_df.iterrows():
        placeholders = ', '.join(['%s'] * len(row))
        cur.execute(f'INSERT INTO "{table_name}" VALUES ({placeholders});', tuple(row))

    conn.commit()
    print(f"✅ {table_name} 테이블에 {len(tag_df)}행 삽입 완료")

conn.close()