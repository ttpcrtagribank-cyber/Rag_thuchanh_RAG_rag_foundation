"""
Application: app.py
Vị trí: buoi_17/app.py
Mục đích: Giao diện Streamlit cho Buổi 17 - RBAC RAG, Audit Trail & AI Compliance Gap Checker.
"""

import os
import sys
import json
import socket
import pandas as pd
import streamlit as st
from pathlib import Path
from dotenv import load_dotenv

# Set page config
st.set_page_config(
    page_title="SECURE RAG & COMPLIANCE — BUỔI 17",
    page_icon="🛡️",
    layout="wide"
)

# Set base path
BUOI_17_DIR = Path(__file__).resolve().parent
if str(BUOI_17_DIR) not in sys.path:
    sys.path.insert(0, str(BUOI_17_DIR))

load_dotenv(BUOI_17_DIR / ".env")

# Import các module logic (Không viết lại logic retrieval/gap trong app.py)
from scripts.internal_lookup import InternalPolicyLookupSystem, INSUFFICIENT_INFO_MSG
from scripts.compliance_gap import ComplianceGapChecker, CATALOG_REPORT_PATH
from scripts.audit_logger import AuditLogger, DEFAULT_AUDIT_LOG_PATH
from scripts.secure_retrieval_adapter import SecureRetrievalAdapter

# Cache system instances
@st.cache_resource
def get_lookup_system():
    return InternalPolicyLookupSystem()

@st.cache_resource
def get_gap_checker():
    return ComplianceGapChecker()

@st.cache_resource
def get_audit_logger():
    return AuditLogger()

lookup_system = get_lookup_system()
gap_checker = get_gap_checker()
audit_logger = get_audit_logger()

# ------------------------------------------------------------------------------
# BANNER TRÊN CÙNG
# ------------------------------------------------------------------------------
st.warning("⚠️ **Demo đào tạo — kết quả AI cần kiểm toán viên xác minh.**")

st.title("🛡️ SECURE RAG & COMPLIANCE — BUỔI 17")
st.caption("RBAC Data Governance, Audit Trail, và AI Compliance Gap Checker trong Ngành Ngân hàng")

# ------------------------------------------------------------------------------
# SIDEBAR: CẤU HÌNH NGƯỜI DÙNG & NEO4J
# ------------------------------------------------------------------------------
st.sidebar.header("🔐 Cấu hình Người dùng Demo")

user_id_demo = st.sidebar.text_input("User ID Demo", value="usr_hr_01")

role_options = ["Admin", "HR_Manager", "Risk_Officer", "Employee", "Guest"]
selected_role = st.sidebar.selectbox("User Role (Vai trò)", role_options, index=1)

st.sidebar.divider()
st.sidebar.header("🌐 Trạng thái Hệ thống Neo4j")

def check_neo4j_port():
    try:
        with socket.create_connection(("localhost", 7687), timeout=1):
            return True
    except Exception:
        return False

neo4j_online = check_neo4j_port()
if neo4j_online:
    st.sidebar.success("🟢 Neo4j Port 7687: Online (bolt://localhost:7687)")
else:
    st.sidebar.info("⚪ Neo4j Port 7687: Not Running (Graph Not Used for Gap Matching)")

# ------------------------------------------------------------------------------
# CÁC TAB CHÍNH
# ------------------------------------------------------------------------------
tab1, tab2, tab3 = st.tabs([
    "🔍 TAB 1: TRA CỨU QUY ĐỊNH",
    "📊 TAB 2: COMPLIANCE GAP CHECKER",
    "📜 TAB 3: AUDIT LOGS"
])

# ==============================================================================
# TAB 1: TRA CỨU QUY ĐỊNH (INTERNAL POLICY LOOKUP)
# ==============================================================================
with tab1:
    st.subheader(" Tra cứu Quy định Nội bộ an toàn với phân quyền RBAC")

    sample_questions = [
        "Tiêu chuẩn bổ nhiệm chức danh thủ kho tiền, thủ quỹ và kiểm ngân trong ngành Ngân hàng được quy định thế nào?",
        "Quy định việc giao nhận, bảo quản, vận chuyển tiền mặt và tài sản quý trong ngành Ngân hàng",
        "Tiêu chuẩn chức danh thủ kho tiền, thủ quỹ và các quy định bổ nhiệm nhân sự nhạy cảm",
        "Tỷ lệ an toàn vốn tối thiểu (CAR) đối với ngân hàng thương mại"
    ]

    selected_sample = st.selectbox("Chọn câu hỏi mẫu hoặc nhập bên dưới:", ["-- Tự nhập câu hỏi --"] + sample_questions)
    
    if selected_sample != "-- Tự nhập câu hỏi --":
        default_q = selected_sample
    else:
        default_q = "Tiêu chuẩn bổ nhiệm chức danh thủ kho tiền, thủ quỹ"

    question = st.text_area("Nhập câu hỏi tra cứu:", value=default_q, height=80)
    top_k = st.slider("Top-k Chunks:", min_value=1, max_value=10, value=5)

    if st.button("🔍 Thực hiện Tra cứu", type="primary"):
        with st.spinner("Đang truy xuất và lọc quyền RBAC..."):
            res = lookup_system.lookup(
                question=question,
                user_role=[selected_role],
                user_id_demo=user_id_demo,
                top_k=top_k
            )

        st.divider()

        # Display Header Metadata
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        col_m1.metric("Request ID", res["request_id"])
        col_m2.metric("User Role", ", ".join(res["access_scope"]))
        col_m3.metric("Filtered Chunks (RBAC)", res["filtered_out_count"])
        
        status_color = "red" if res["status"] == "DENIED" else "green"
        col_m4.markdown(f"**Access Decision:** :{status_color}[**{res['status']}**]")

        # Display LLM Answer
        st.subheader("💡 Câu trả lời từ AI")
        if res["status"] == "DENIED" or res["answer"] == INSUFFICIENT_INFO_MSG:
            st.error(f"⛔ **{res['answer']}**")
        else:
            st.success(res["answer"])

        # Display Citations & Retrieved Chunks (ONLY if NOT DENIED)
        if res["status"] != "DENIED" and res["retrieved_results"]:
            st.subheader("📌 Danh sách Trích dẫn (Citations)")
            for cit in res["citations"]:
                st.code(cit, language="text")

            st.subheader("📄 Chi tiết Chunks được phép truy cập")
            for item in res["retrieved_results"]:
                with st.expander(f"Rank {item['rank']}: [{item['chunk_id']}] {item['title'][:60]}..."):
                    st.write(f"**Document ID:** `{item['document_id']}`")
                    st.write(f"**Article:** {item['article']}")
                    st.write(f"**Allowed Roles:** `{item['allowed_roles']}`")
                    st.write(f"**Access Decision:** `{item['access_decision']}`")
                    st.markdown("**Nội dung:**")
                    st.info(item["text"])
        elif res["status"] == "DENIED":
            st.warning("🔒 **BẢO MẬT:** Không hiển thị snippet hoặc citation do người dùng không có quyền xem các tài liệu liên quan.")

# ==============================================================================
# TAB 2: COMPLIANCE GAP CHECKER
# ==============================================================================
with tab2:
    st.subheader("📊 AI Compliance Gap Checker (NHNN Requirement vs Internal Policy)")

    # Display Data Readiness Notice
    is_ready = gap_checker.check_data_readiness()
    if not is_ready:
        st.warning("⚠️ **DATA GAP NOTICE:** Tập dữ liệu hiện tại chứa 15 văn bản Quản lý Nhà nước và **KHÔNG có văn bản Quy định Nội bộ (INTERNAL_POLICY)**.")
        st.info("Hệ thống tuân thủ nguyên tắc không sinh kết luận giả và đánh dấu trạng thái: **`CHUA_DU_BANG_CHUNG`**.")

    sample_nhnn_reqs = [
        ("Vận chuyển tiền mặt, tài sản quý phải sử dụng xe chuyên dùng và có xe hộ tống.", "[01/2014/TT-NHNN | Điều 50]"),
        ("Thủ kho tiền, thủ quỹ phải đáp ứng tiêu chuẩn trình độ chuyên môn, lý lịch tư pháp sạch và không được là người thân của Kế toán trưởng.", "[01/2014/TT-NHNN | Điều 24]"),
        ("Tỷ lệ an toàn vốn tối thiểu (CAR) của ngân hàng thương mại phải đạt ít nhất 8%.", "[41/2016/TT-NHNN | Điều 3]")
    ]

    selected_req_idx = st.selectbox(
        "Chọn Yêu cầu NHNN (External Requirement) để kiểm tra:",
        range(len(sample_nhnn_reqs)),
        format_func=lambda i: f"{sample_nhnn_reqs[i][1]} - {sample_nhnn_reqs[i][0]}"
    )

    req_text = sample_nhnn_reqs[selected_req_idx][0]
    req_cit = sample_nhnn_reqs[selected_req_idx][1]

    if st.button("⚡ Phân tích Compliance Gap", type="primary"):
        with st.spinner("Đang đối chiếu quy định..."):
            gap_res = gap_checker.analyze_requirement(req_text, req_cit, user_role=[selected_role])

        st.divider()
        col_g1, col_g2, col_g3 = st.columns(3)
        col_g1.metric("Classification", gap_res["classification"])
        col_g2.metric("Confidence Score", f"{gap_res['confidence'] * 100:.0f}%")
        col_g3.metric("Review Status", gap_res["review_status"])

        st.subheader("📋 Bảng Evidence Package & Chi tiết Gap")
        gap_df = pd.DataFrame([{
            "External Requirement": gap_res["external_requirement"],
            "External Citation": gap_res["external_citation"],
            "Internal Evidence": gap_res["internal_evidence"],
            "Internal Citation": gap_res["internal_citation"],
            "Classification": gap_res["classification"],
            "Reason": gap_res["reason"],
            "Confidence": gap_res["confidence"],
            "Review Status": gap_res["review_status"]
        }])
        st.dataframe(gap_df, width=1200)

# ==============================================================================
# TAB 3: AUDIT LOGS
# ==============================================================================
with tab3:
    st.subheader("📜 Nhật ký Kiểm toán (Audit Trail)")
    st.caption("Chỉ hiển thị các Audit Events phù hợp với Người dùng / Vai trò Demo hiện tại. Bảo mật 100% bí mật.")

    audit_file = DEFAULT_AUDIT_LOG_PATH
    if not audit_file.exists():
        st.info("Chưa có nhật ký kiểm toán. Hãy thực hiện tra cứu ở Tab 1 để phát sinh log.")
    else:
        with open(audit_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        logs = []
        for line in lines:
            try:
                data = json.loads(line)
                # Báo mật: Loại bỏ secret, password, api_key nếu có
                data.pop("password", None)
                data.pop("api_key", None)
                data.pop("secret", None)
                
                # Lọc sự kiện phù hợp với user_id_demo hoặc user_role hiện tại (hoặc Admin xem tất cả)
                event_roles = data.get("user_role", [])
                event_user = data.get("user_id_demo", "")

                if selected_role == "Admin" or event_user == user_id_demo or selected_role in event_roles:
                    logs.append(data)
            except Exception:
                pass

        if not logs:
            st.warning(f"Không có audit log nào phù hợp với User '{user_id_demo}' / Role '{selected_role}'.")
        else:
            st.success(f"Hiển thị {len(logs)} sự kiện kiểm toán được ghi nhận:")
            log_df = pd.DataFrame(logs)
            st.dataframe(log_df, width=1200)
