import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import numpy as np
import os
import base64
from datetime import datetime, timedelta

# =====================================================
# 1. 페이지 설정
# =====================================================
st.set_page_config(
    layout="wide",
    page_title="🛰️ Attack 상세 모니터링",
    initial_sidebar_state="expanded"
)

# =====================================================
# 2. 배경 이미지 + 공통 CSS
# =====================================================
def set_bg(image_file):
    if not os.path.exists(image_file):
        # 배경 이미지가 없을 경우 기본 어두운 배경색 지정
        st.markdown("""
        <style>
        .stApp { background-color: #0e1117; }
        </style>
        """, unsafe_allow_html=True)
        return

    with open(image_file, "rb") as f:
        encoded = base64.b64encode(f.read()).decode()

    st.markdown(f"""
    <style>
    /* ===== 전체 배경 ===== */
    .stApp {{
        background: 
            linear-gradient(rgba(5,15,25,0.45), rgba(5,15,25,0.45)),
            url("data:image/jpg;base64,{encoded}");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }}

    /* ===== 타이틀 카드 ===== */
    .title-card {{
        background: rgba(10,20,35,0.55);
        backdrop-filter: blur(10px);
        border-radius: 18px;
        padding: 22px 30px;
        margin: 10px auto 25px auto;
        width: fit-content;
        box-shadow: 0 0 30px rgba(0,229,255,0.25);
    }}

    .attack-title {{
        text-align: center;
        font-size: 42px;
        font-weight: 800;
        color: #00e5ff;
        margin: 0;
    }}

    /* ===== 그래프 및 테이블 카드 ===== */
    div[data-testid="stPlotlyChart"], div[data-testid="stDataFrame"] {{
        background: rgba(10,20,35,0.55);
        backdrop-filter: blur(8px);
        border-radius: 14px;
        padding: 10px;
    }}
    </style>
    """, unsafe_allow_html=True)

set_bg("background.jpg")

# =====================================================
# 3. 데이터 생성 / 로드
# =====================================================
FILE_PATH = "attack_log.csv"

def generate_rows(n=100):
    attack_types = ["05.CTI 공격", "00.평판 탐지", "01.침입 시도", "02.악성코드 유포"]
    orgs = ["A기관", "B기관", "C기관", "D기관"]
    countries = ["South Korea", "United States", "China", "Russia"]
    # IP 대역을 조금 줄여서 중복 IP가 나오게 유도 (분석을 위해)
    ips = [f"192.168.0.{x}" for x in range(1, 20)]

    return pd.DataFrame({
        "발생시간": [(datetime.now() - timedelta(minutes=np.random.randint(0, 300))) for _ in range(n)],
        "출발지IP": np.random.choice(ips, n), # 위에서 만든 IP 풀에서 랜덤 선택
        "출발지국가": np.random.choice(countries, n),
        "목적지기관": np.random.choice(orgs, n),
        "공격유형": np.random.choice(attack_types, n),
        "건수": np.random.randint(1, 10, n)
    })

def load_data():
    if not os.path.exists(FILE_PATH):
        df = generate_rows(500)
        df.to_csv(FILE_PATH, index=False, encoding="utf-8-sig")

    df = pd.read_csv(FILE_PATH)
    df["발생시간"] = pd.to_datetime(df["발생시간"])
    return df

if 'df' not in st.session_state:
    st.session_state.df = load_data()

df_original = st.session_state.df.copy() # 원본 데이터 보존

# =====================================================
# [추가] 사이드바 필터링 (IP 검색)
# =====================================================
with st.sidebar:
    st.header("🔍 상세 검색")
    search_ip = st.text_input("출발지 IP 검색", placeholder="예: 192.168.")

    # 검색어가 있으면 데이터 필터링
    if search_ip:
        df = df_original[df_original['출발지IP'].str.contains(search_ip)]
    else:
        df = df_original

    st.markdown("---")
    if st.button("🔄 데이터 새로고침 (+100)"):
        new_data = generate_rows(100)
        updated_df = pd.concat([df_original, new_data], ignore_index=True)
        updated_df.to_csv(FILE_PATH, index=False, encoding="utf-8-sig")
        st.session_state.df = updated_df
        st.rerun()

# =====================================================
# 4. 헤더
# =====================================================
st.markdown("""
<div class="title-card">
    <div class="attack-title">
        🛰️ ATTACK 실시간 관제 대시보드
    </div>
</div>
""", unsafe_allow_html=True)

# =====================================================
# 5. 상단 영역
# =====================================================
col1, col2 = st.columns([3, 1])

with col1:
    st.subheader("📊 시간대별 공격 탐지량")
    if not df.empty:
        df_hour = df.set_index("발생시간").resample("H").size().reset_index(name="count")
        fig = go.Figure()
        fig.add_bar(x=df_hour["발생시간"], y=df_hour["count"], name="건수")
        fig.add_scatter(x=df_hour["발생시간"], y=df_hour["count"], mode="lines+markers", name="추세")
        fig.update_layout(template="plotly_dark", height=320, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("검색 결과가 없습니다.")

with col2:
    st.subheader("📈 상태")
    st.metric("TOTAL EVENTS", f"{len(df):,}")
    st.metric("TOTAL HITS", f"{df['건수'].sum():,}" if not df.empty else "0")

    if search_ip:
        st.warning(f"🔎 검색 필터 적용 중: '{search_ip}'")

st.divider()

# =====================================================
# [추가] IP 분석 전용 섹션 (요청하신 기능)
# =====================================================
st.subheader("🎯 IP별 공격 유형 상세 분석")

if not df.empty:
    # 1. 데이터 집계: IP와 공격유형별로 건수 합계
    ip_analysis = df.groupby(["출발지IP", "공격유형"])["건수"].sum().reset_index()

    # 2. 상위 10개 IP 추출 (너무 많으면 그래프가 깨지므로)
    top_ips = df.groupby("출발지IP")["건수"].sum().nlargest(15).index
    filtered_ip_analysis = ip_analysis[ip_analysis["출발지IP"].isin(top_ips)]

    # 3. 스택 막대 그래프 생성
    fig_ip = px.bar(
        filtered_ip_analysis,
        x="출발지IP",
        y="건수",
        color="공격유형",
        title="Top 15 Attacking IPs Breakdown (Color by Type)",
        text="건수"
    )

    fig_ip.update_layout(
        template="plotly_dark",
        height=400,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis_title="Attacker IP",
        yaxis_title="Total Hits"
    )
    st.plotly_chart(fig_ip, use_container_width=True)
else:
    st.write("데이터가 없습니다.")

st.divider()

# =====================================================
# 6. 중단 그래프
# =====================================================
mid1, mid2, mid3 = st.columns(3)

def transparent_layout(fig, h=280):
    fig.update_layout(
        template="plotly_dark",
        height=h,
        margin=dict(l=10, r=10, t=40, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)"
    )
    return fig

if not df.empty:
    with mid1:
        st.subheader("🌐 국가별 분포")
        fig = px.pie(df, names="출발지국가", hole=0.4)
        st.plotly_chart(transparent_layout(fig), use_container_width=True)

    with mid2:
        st.subheader("🏢 기관별 공격건수")
        df_org = df.groupby("목적지기관")["건수"].sum().reset_index()
        fig = px.bar(df_org, x="건수", y="목적지기관", orientation="h", color="목적지기관")
        st.plotly_chart(transparent_layout(fig), use_container_width=True)

    with mid3:
        st.subheader("🛡️ 공격 유형 비율")
        df_type = df.groupby("공격유형").size().reset_index(name="count")
        fig = px.funnel(df_type, x="count", y="공격유형")
        st.plotly_chart(transparent_layout(fig), use_container_width=True)

st.divider()

# =====================================================
# 7. 하단 테이블
# =====================================================
st.subheader("📝 원본 경보 발생 현황")

def highlight_attack(row):
    if row["공격유형"] == "02.악성코드 유포":
        return ["background-color: #4a0000; color: white"] * len(row)
    if row["공격유형"] == "01.침입 시도":
        return ["background-color: #3e3e00; color: #ffd700"] * len(row)
    return [""] * len(row)

if not df.empty:
    styled_df = (
        df.sort_values("발생시간", ascending=False)
        .head(100)
        .style.apply(highlight_attack, axis=1)
    )
    st.dataframe(styled_df, use_container_width=True, height=400)
else:
    st.write("수집된 데이터가 없습니다.")