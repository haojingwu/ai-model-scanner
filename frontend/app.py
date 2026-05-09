import streamlit as st
import requests, json, time

st.set_page_config(page_title="AI模型供应链安全检测平台", page_icon="🛡️", layout="wide")
st.title("🛡️ AI模型供应链安全检测平台")
st.markdown("检测 PyTorch / Keras 模型文件中的恶意载荷")

API_URL = "http://localhost:8000/api/v1"

# 侧边栏
with st.sidebar:
    st.header("⚙️ 检测配置")
    scan_mode = st.radio("分析模式", ["快速检测 (静态+AI)", "深度检测 (含沙箱)"],
                         help="快速检测仅做静态分析和AI判定；深度检测会提交到沙箱动态分析")
    st.divider()
    st.markdown("### 📋 检测能力")
    st.markdown("- ✅ pickle 操作码静态分析")
    st.markdown("- ✅ AI 异常检测 (Isolation Forest)")
    st.markdown("- ✅ Docker 沙箱动态分析")
    st.markdown("- 🔜 Keras H5 模型支持")
    st.divider()
    st.markdown("### 🔗 链接")
    st.markdown("[GitHub 仓库](https://github.com/haojingwu/ai-model-scanner)")

# 主区域
uploaded_file = st.file_uploader(
    "上传模型文件",
    type=['pth', 'pt', 'h5', 'hdf5', 'keras'],
    help="支持 PyTorch (.pth/.pt) 和 Keras (.h5) 模型文件"
)

if uploaded_file:
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.info(f"📄 文件名: {uploaded_file.name}")
        st.caption(f"大小: {uploaded_file.size / 1024:.1f} KB")
    
    if st.button("🔍 开始扫描", type="primary", use_container_width=True):
        with st.spinner("正在分析中..."):
            files = {'file': (uploaded_file.name, uploaded_file.getvalue())}
            response = requests.post(f"{API_URL}/scan", files=files)
            result = response.json()
            
            scan_id = result['scan_id']
            risk_level = result['risk_level']
            
            # 风险等级展示
            risk_color = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢', 'PENDING': '🔄', 'ERROR': '⚪'}
            
            st.markdown("---")
            st.subheader("📊 扫描结果")
            
            metric_cols = st.columns(4)
            with metric_cols[0]:
                st.metric("风险等级", f"{risk_color.get(risk_level, '⚪')} {risk_level}")
            with metric_cols[1]:
                st.metric("扫描阶段", result.get('scan_stage', 'N/A'))
            with metric_cols[2]:
                st.metric("扫描ID", scan_id[:8] + "...")
            
            # AI检测详情
            if 'details' in result:
                details = result['details']
                
                # 静态分析
                with st.expander("📝 静态分析详情", expanded=True):
                    static = details.get('static_analysis', {})
                    flag_cols = st.columns(3)
                    with flag_cols[0]:
                        high_risk = static.get('risk_flags', {}).get('has_exec_opcodes', False)
                        st.metric("执行操作码", "⚠️ 发现" if high_risk else "✅ 正常")
                    with flag_cols[1]:
                        kw = static.get('risk_flags', {}).get('has_suspicious_keywords', False)
                        st.metric("可疑关键词", "⚠️ 发现" if kw else "✅ 正常")
                    with flag_cols[2]:
                        he = static.get('risk_flags', {}).get('has_high_entropy_blocks', False)
                        st.metric("高熵区块", "⚠️ 发现" if he else "✅ 正常")
                    
                    if static.get('suspicious_ops'):
                        st.warning("🔍 可疑操作码:")
                        for op in static['suspicious_ops']:
                            st.code(f"{op['opcode']}: {op['arg'][:150]}")
                
                # AI检测
                with st.expander("🤖 AI异常检测", expanded=True):
                    ai = details.get('ai_detection', {})
                    ai_cols = st.columns(2)
                    with ai_cols[0]:
                        st.metric("AI判定", "⚠️ 异常" if ai.get('is_anomaly') else "✅ 正常")
                    with ai_cols[1]:
                        st.metric("异常分数", f"{ai.get('anomaly_score', 0):.3f}")
                    st.progress(ai.get('anomaly_score', 0))
            
            # 沙箱结果轮询
            if result.get('scan_stage') == 'sandbox' and 'task_id' in result:
                st.info(f"⏳ 沙箱分析进行中... (任务ID: {result['task_id'][:8]}...)")
                
                with st.spinner("等待沙箱结果..."):
                    for _ in range(30):
                        time.sleep(2)
                        r = requests.get(f"{API_URL}/result/{scan_id}")
                        if r.status_code == 200:
                            sandbox_result = r.json()
                            if sandbox_result.get('status') != 'pending':
                                st.success("沙箱分析完成!")
                                with st.expander("📦 沙箱分析报告"):
                                    st.json(sandbox_result)
                                break
        
        st.divider()
        st.caption("扫描完成 · 数据仅保存在本地")
