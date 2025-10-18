import sqlite3
import pandas as pd
import os 

db_path = r"C:\Users\zlfnf\Desktop\q2wr423\243\autopsy.db"  # 🔸 실제 DB 경로로 바꿔주세요
conn = sqlite3.connect(db_path)
cursor = conn.cursor()


view_name = "aaaaaa"
sql_code = f"""
-- 🔹 통합 뷰 (aaaaaa) — Exfiltration 조건 추가됨
DROP VIEW IF EXISTS {view_name};

CREATE VIEW {view_name} AS
SELECT * FROM (
    -- 🧩 1. Blackboard 아티팩트
    SELECT
        a.artifact_id AS id,
        art.display_name AS source,
        art.display_name AS artifact_name,
        COALESCE(f.name, NULL) AS file_name,
        GROUP_CONCAT(
            att.display_name || ': ' ||
            CASE
                WHEN (att.display_name LIKE '%Date%' OR att.display_name LIKE '%Time%' OR att.display_name LIKE '%Last Write%')
                     AND b.value_int64 > 1000000000
                THEN datetime(b.value_int64, 'unixepoch', 'localtime')
                WHEN att.display_name LIKE '%Associated Artifact%'
                THEN COALESCE(ff.name, CAST(b.value_int64 AS TEXT), b.value_text)
                ELSE COALESCE(b.value_text,
                              CAST(b.value_int32 AS TEXT),
                              CAST(b.value_int64 AS TEXT),
                              CAST(b.value_double AS TEXT))
            END,
            ' | '
        ) AS full_description,

        CASE
            ----------------------------------------------------------------
            -- 🔥 Exfiltration (유출) 관련 조건: 가능한 키워드/아티팩트 우선 검사
            -- 브라우저 업로드, POST/PUT, 이메일 첨부, 네트워크/트래픽/pcap, FTP/SFTP, SMTP/IMAP
            WHEN art.display_name LIKE '%Upload%' 
                 OR art.display_name LIKE '%Upload Details%' 
                 OR art.display_name LIKE '%File Upload%'
                 OR art.display_name LIKE '%Network%' 
                 OR art.display_name LIKE '%Traffic%' 
                 OR art.display_name LIKE '%PCAP%' 
                 OR art.display_name LIKE '%Packet Capture%' 
                 OR art.display_name LIKE '%Socket%' 
                 OR art.display_name LIKE '%SMTP%' 
                 OR art.display_name LIKE '%IMAP%' 
                 OR art.display_name LIKE '%POP3%' 
                 OR art.display_name LIKE '%Email%' 
                 OR art.display_name LIKE '%Attachment%' 
                 OR art.display_name LIKE '%FTP%' 
                 OR art.display_name LIKE '%SFTP%' 
                 OR art.display_name LIKE '%HTTP Request%' 
                 OR art.display_name LIKE '%HTTP%' 
                 OR LOWER(b.value_text) LIKE '%upload%' 
                 OR LOWER(b.value_text) LIKE '%attachment%' 
                 OR LOWER(b.value_text) LIKE '%post%' 
                 OR LOWER(b.value_text) LIKE '%put%' 
                 OR LOWER(b.value_text) LIKE '%smtp%' 
                 OR LOWER(b.value_text) LIKE '%imap%' 
                 OR LOWER(b.value_text) LIKE '%ftp%' 
                 OR LOWER(att.display_name) LIKE '%upload%' 
                 OR LOWER(att.display_name) LIKE '%attachment%' 
            THEN 'Exfiltration'

            ----------------------------------------------------------------
            -- 사용자 활동 (브라우징, Recent, Shell Bags, USB)
            WHEN art.display_name LIKE '%Shell Bags%' OR art.display_name LIKE '%Recent Document%' THEN 'UserActivity'
            WHEN art.display_name LIKE '%USB Device Attached%' OR art.display_name LIKE '%USB%' THEN 'UserActivity'
            WHEN art.display_name LIKE '%History%' OR art.display_name LIKE '%Web History%' THEN 'UserActivity'
            WHEN art.display_name LIKE '%Favicon%' OR art.display_name LIKE '%Favicons%' THEN 'UserActivity'
            WHEN art.display_name LIKE '%Chromium%' OR art.display_name LIKE '%Chrome%' OR art.display_name LIKE '%Firefox%' THEN 'UserActivity'

            ----------------------------------------------------------------
            -- 시스템 관련
            WHEN art.display_name LIKE '%Operating System%' OR art.display_name LIKE '%Accounts%' OR art.display_name LIKE '%Host%' THEN 'System'

            ----------------------------------------------------------------
            -- 설치 관련
            WHEN art.display_name LIKE '%Installed%' OR art.display_name LIKE '%Installed Programs%' THEN 'Installation'
            WHEN art.display_name LIKE '%Extensions%' OR art.display_name LIKE '%Secure Preferences%' OR art.display_name LIKE '%Extension%' THEN 'Installation'

            ----------------------------------------------------------------
            -- 실행 관련 (프로세스/Prefetch/Run 등)
            WHEN art.display_name LIKE '%Prefetch%' OR art.display_name LIKE '%Run%' OR art.display_name LIKE '%Execution%' OR art.display_name LIKE '%Process%' THEN 'Execution'

            WHEN art.display_name LIKE '%Associated Object%' 
                 AND (
                    LOWER(ff.name) LIKE '%.exe' OR LOWER(ff.name) LIKE '%.bat' OR
                    LOWER(ff.name) LIKE '%.cmd' OR LOWER(ff.name) LIKE '%.ps1' OR
                    LOWER(ff.name) LIKE '%.msi'
                 ) THEN 'Execution'

            WHEN art.display_name LIKE '%Associated Object%' 
                 AND (LOWER(ff.name) LIKE '%data_%' OR LOWER(ff.name) LIKE '%f_%' OR LOWER(ff.name) LIKE '%obj_%') THEN 'System'
            WHEN art.display_name LIKE '%Associated Object%' 
                 AND (LOWER(b.value_text) LIKE '%history%' OR LOWER(att.display_name) LIKE '%history%') THEN 'UserActivity'

            ----------------------------------------------------------------
            -- 메타데이터 관련
            WHEN art.display_name LIKE '%Data Source%' 
                 OR art.display_name LIKE '%Drive%' 
                 OR art.display_name LIKE '%Partition%' 
                 OR art.display_name LIKE '%Volume%' 
                 OR art.display_name LIKE '%MFT%' 
                 OR art.display_name LIKE '%File Object%' 
                 OR art.display_name LIKE '%File Metadata%' THEN 'Metadata'
            WHEN art.display_name LIKE '%Profiles%' OR art.display_name LIKE '%Local State%' THEN 'Metadata'

            ELSE 'Unknown'
        END AS tag

    FROM blackboard_artifacts AS a
        JOIN blackboard_artifact_types AS art ON a.artifact_type_id = art.artifact_type_id
        JOIN blackboard_attributes AS b ON a.artifact_id = b.artifact_id
        JOIN blackboard_attribute_types AS att ON b.attribute_type_id = att.attribute_type_id
        LEFT JOIN tsk_files AS f ON a.obj_id = f.obj_id
        LEFT JOIN blackboard_artifacts AS af ON b.value_int64 = af.artifact_id
        LEFT JOIN tsk_files AS ff ON af.obj_id = ff.obj_id
    GROUP BY a.artifact_id, art.display_name

    UNION ALL

    -- 🧩 2. OS Account
    SELECT
        a.os_account_obj_id AS id,
        'OS Account Table' AS source,
        'OS Account' AS artifact_name,
        NULL AS file_name,
        TRIM(
            COALESCE('User=' || a.login_name, '') ||
            CASE WHEN r.realm_name IS NOT NULL THEN ' | Realm=' || r.realm_name ELSE '' END ||
            CASE WHEN a.realm_id IS NOT NULL THEN ' | realm_id=' || CAST(a.realm_id AS TEXT) ELSE '' END ||
            CASE WHEN a.status IS NOT NULL THEN ' | status=' || CAST(a.status AS TEXT) ELSE '' END ||
            CASE WHEN a.type IS NOT NULL THEN ' | type=' || CAST(a.type AS TEXT) ELSE '' END ||
            CASE WHEN a.created_date > 1000000000 THEN ' | created_date=' || datetime(a.created_date, 'unixepoch', 'localtime') ELSE '' END
        ) AS full_description,
        'System' AS tag
    FROM tsk_os_accounts AS a
        LEFT JOIN tsk_os_account_instances AS i ON a.os_account_obj_id = i.os_account_obj_id
        LEFT JOIN tsk_os_account_realms AS r ON a.realm_id = r.id

    UNION ALL

    -- 🧩 3. Account System
    SELECT
        acc.account_id AS id,
        'Account System' AS source,
        COALESCE(at.display_name, at.type_name, 'Account') AS artifact_name,
        NULL AS file_name,
        (
            'Account ID=' || COALESCE(CAST(acc.account_id AS TEXT), '') ||
            ' | Unique Identifier=' || COALESCE(acc.account_unique_identifier, '') ||
            ' | Account Type=' || COALESCE(at.type_name, '') ||
            ' | Display Name=' || COALESCE(at.display_name, '') ||
            CASE WHEN rel.relationship_id IS NOT NULL THEN
                ' | Relationship: From Account ' || COALESCE(CAST(rel.account1_id AS TEXT), '') ||
                ' → To Account ' || COALESCE(CAST(rel.account2_id AS TEXT), '') ||
                CASE WHEN rel.relationship_type IS NOT NULL THEN ' (Type=' || rel.relationship_type || ')' ELSE '' END ||
                CASE WHEN rel.date_time > 1000000000 THEN ' | Date=' || datetime(rel.date_time, 'unixepoch', 'localtime') ELSE '' END
            ELSE '' END
        ) AS full_description,
        'System' AS tag
    FROM accounts AS acc
        LEFT JOIN account_types AS at ON acc.account_type_id = at.account_type_id
        LEFT JOIN account_relationships AS rel ON acc.account_id = rel.account1_id OR acc.account_id = rel.account2_id

    UNION ALL

    -- 🧩 4. Event Log (Event-level도 Exfiltration 키워드 검사 추가)
    SELECT
        e.event_id AS id,
        'Event Log' AS source,
        COALESCE(et.display_name, 'Event') AS artifact_name,
        NULL AS file_name,
        'Description=' || COALESCE(ed.full_description, 'Event Log Entry') || 
        ' | Time=' || datetime(e.time, 'unixepoch', 'localtime') AS full_description,
        CASE
            WHEN LOWER(COALESCE(et.display_name, '')) LIKE '%smtp%' OR LOWER(COALESCE(ed.full_description, '')) LIKE '%smtp%' THEN 'Exfiltration'
            WHEN LOWER(COALESCE(et.display_name, '')) LIKE '%imap%' OR LOWER(COALESCE(ed.full_description, '')) LIKE '%imap%' THEN 'Exfiltration'
            WHEN LOWER(COALESCE(et.display_name, '')) LIKE '%ftp%' OR LOWER(COALESCE(ed.full_description, '')) LIKE '%ftp%' THEN 'Exfiltration'
            WHEN LOWER(COALESCE(et.display_name, '')) LIKE '%http%' OR LOWER(COALESCE(ed.full_description, '')) LIKE '%http%' OR LOWER(COALESCE(ed.full_description, '')) LIKE '%post%' THEN 'Exfiltration'
            WHEN et.display_name LIKE '%Process%' OR et.display_name LIKE '%Execution%' OR et.display_name LIKE '%Run%' OR et.display_name LIKE '%Start%' THEN 'Execution'
            WHEN et.display_name LIKE '%Created%' OR et.display_name LIKE '%Modified%' OR et.display_name LIKE '%Accessed%' OR et.display_name LIKE '%Changed%' THEN 'UserActivity'
            ELSE 'Unknown'
        END AS tag
    FROM tsk_events AS e
        LEFT JOIN tsk_event_types AS et ON e.event_type_id = et.event_type_id
        LEFT JOIN tsk_event_descriptions AS ed ON e.event_description_id = ed.event_description_id

    UNION ALL

    -- 🧩 5. Host
    SELECT
        h.id AS id,
        'Host Table' AS source,
        'Host' AS artifact_name,
        NULL AS file_name,
        'Name=' || COALESCE(h.name, '') ||
        CASE WHEN ha.address IS NOT NULL THEN ' | Address=' || ha.address ELSE '' END ||
        CASE WHEN m.source_obj_id IS NOT NULL THEN ' | source_obj_id=' || m.source_obj_id ELSE '' END AS full_description,
        'System' AS tag
    FROM tsk_hosts AS h
        LEFT JOIN tsk_host_address_map AS m ON h.id = m.host_id
        LEFT JOIN tsk_host_addresses AS ha ON m.addr_obj_id = ha.id
        LEFT JOIN tsk_host_address_usage AS u ON u.addr_obj_id = ha.id

    UNION ALL

    -- 🧩 6. File Metadata
    SELECT
        f.obj_id AS id,
        'File Object' AS source,
        'File Metadata' AS artifact_name,
        f.name AS file_name,
        (
            'Full Path: ' || COALESCE(f.parent_path, '[Unknown]') || f.name ||
            ' | Size: ' || COALESCE(CAST(f.size AS TEXT), '[NULL]') ||
            ' | Created: ' || COALESCE(datetime(f.crtime, 'unixepoch', 'localtime'), '[NULL]') ||
            ' | Modified: ' || COALESCE(datetime(f.mtime, 'unixepoch', 'localtime'), '[NULL]') ||
            ' | Accessed: ' || COALESCE(datetime(f.atime, 'unixepoch', 'localtime'), '[NULL]') ||
            ' | Changed: ' || COALESCE(datetime(f.ctime, 'unixepoch', 'localtime'), '[NULL]') ||
            CASE WHEN f.extension IS NOT NULL THEN ' | Extension: ' || f.extension ELSE '' END ||
            CASE WHEN f.mime_type IS NOT NULL THEN ' | MIME: ' || f.mime_type ELSE '' END
        ) AS full_description,
        'Metadata' AS tag
    FROM tsk_files AS f
    WHERE f.name IS NOT NULL
)
ORDER BY id;

------------------------------------------------------------
-- 🔸 Tag별 하위 뷰 생성 (Unknown 제외)
------------------------------------------------------------

-- 1️⃣ System
DROP VIEW IF EXISTS view_system;
CREATE VIEW view_system AS
SELECT * FROM aaaaaa
WHERE tag = 'System'
ORDER BY id;

-- 2️⃣ Execution
DROP VIEW IF EXISTS view_execution;
CREATE VIEW view_execution AS
SELECT * FROM aaaaaa
WHERE tag = 'Execution'
ORDER BY id;

-- 3️⃣ UserActivity
DROP VIEW IF EXISTS view_useractivity;
CREATE VIEW view_useractivity AS
SELECT * FROM aaaaaa
WHERE tag = 'UserActivity'
ORDER BY id;

-- 4️⃣ Metadata
DROP VIEW IF EXISTS view_metadata;
CREATE VIEW view_metadata AS
SELECT * FROM aaaaaa
WHERE tag = 'Metadata'
ORDER BY id;

-- 5️⃣ Installation
DROP VIEW IF EXISTS view_installation;
CREATE VIEW view_installation AS
SELECT * FROM aaaaaa
WHERE tag = 'Installation'
ORDER BY id;

-- 6️⃣ Exfiltration (유출)
DROP VIEW IF EXISTS view_exfiltration;
CREATE VIEW view_exfiltration AS
SELECT * FROM aaaaaa
WHERE tag = 'Exfiltration'
ORDER BY id;
"""
cursor.executescript(sql_code)
conn.commit()

# 3️⃣ 뷰 테이블 불러오기
output_dir = r"C:\Users\zlfnf\Desktop\q2wr423\243"
os.makedirs(output_dir, exist_ok=True)

# 태그별 뷰 이름 목록
views = [
    "view_system",
    "view_execution",
    "view_useractivity",
    "view_metadata",
    "view_installation",
    "view_exfiltration"
]

# 각 뷰별 CSV/JSON 저장
for v in views:
    df = pd.read_sql_query(f"SELECT * FROM {v};", conn)
    csv_path = os.path.join(output_dir, f"{v}.csv")
    json_path = os.path.join(output_dir, f"{v}.json")
    df.to_csv(csv_path, index=False, encoding="utf-8-sig")
    df.to_json(json_path, orient="records", force_ascii=False, indent=2)
    print(f"✅ {v} 저장 완료:\n   CSV: {csv_path}\n   JSON: {json_path}\n")

print("🎉 모든 태그별 데이터 내보내기 완료!")

# 4️⃣ DB 닫기
conn.close()