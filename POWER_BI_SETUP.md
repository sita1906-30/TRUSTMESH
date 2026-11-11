# TRUSTMESH — Power BI Analytics & Dashboard Integration Guide
**Phase 4, Task 4: Scam Intelligence & Telemetry Visualization**

---

## 1. Executive Summary & Architecture

The **TRUSTMESH Business Intelligence Layer** transforms privacy-preserving scam assessment telemetry into actionable security intelligence. It allows institutional administrators, cybersecurity educators, and academic evaluators to analyze threat vectors, risk patterns, and temporal trends using **Power BI Desktop** (Free edition, no paid Pro or Premium licenses required).

### High-Level Analytics Flow

```
                      +------------------------------------------+
                      |         TRUSTMESH Security Platform      |
                      |    (Heuristic Detection & Incident Store)|
                      +--------------------+---------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |       Database Analytics Views (SQL)     |
                      |  - v_analytics_overview                  |
                      |  - v_risk_level_distribution             |
                      |  - v_risk_signal_frequency               |
                      |  - v_assessment_trends                   |
                      +--------------------+---------------------+
                                           |
                  +------------------------+------------------------+
                  |                                                 |
                  v                                                 v
    [Method 1: Anonymized CSV Export]             [Method 2: Azure SQL Direct Connection]
    - Endpoint: /api/analytics/export             - Server: myserver.database.windows.net
    - Format: RFC-4180 CSV                        - Database: trustmesh-db
    - Zero PII, no credentials                   - DirectQuery or Import Mode
                  |                                                 |
                  +------------------------+------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |            Microsoft Power BI            |
                      |  Page 1: Executive Threat Overview       |
                      |  Page 2: Scam Signal Intelligence        |
                      |  Page 3: Temporal Threat Trend Analysis  |
                      +------------------------------------------+
```

---

## 2. Privacy & Anonymization Architecture

TRUSTMESH strictly enforces security and privacy in all analytics outputs. Telemetry records contain **zero personally identifiable information (PII)**:

| Category | Status | Implementation Guarantee |
| :--- | :--- | :--- |
| **User Passwords / Hashes** | **STRICTLY EXCLUDED** | Password hashes (`password_hash`) are never queried or exported. |
| **Email Addresses & Names** | **STRICTLY EXCLUDED** | Account emails and display names are absent from all views and CSV outputs. |
| **Raw Message Content** | **STRICTLY EXCLUDED** | In compliance with Phase 2/3 privacy rules, raw messages are discarded after analysis. Only a one-way cryptographic fingerprint (`content_fingerprint_sha256`) is stored. |
| **Full URLs & Private Tokens** | **STRICTLY EXCLUDED** | Only structural classifications (`url`, `message`, `mixed`) and triggered heuristic indicators are exported. |
| **Administrative Access** | **ROLE-PROTECTED** | All analytics endpoints and CSV exports require authenticated **ADMIN** role (`@role_required("admin")`). |

---

## 3. Database Analytics Views

The application provides four dedicated relational views implemented consistently across both **SQLite** and **Microsoft Azure SQL Database**:

### 1. `v_analytics_overview`
Aggregates top-level KPI metrics across the platform:
- `total_assessments`: Total number of completed risk evaluations.
- `total_low_risk`: Count of evaluations categorized as *Lower detected risk*.
- `total_medium_risk`: Count of evaluations categorized as *Suspicious*.
- `total_high_risk`: Count of evaluations categorized as *High risk*.
- `avg_risk_score`: Platform-wide average risk score (0.0 to 100.0).
- `pct_low_risk`: Percentage of low-risk evaluations.
- `pct_medium_risk`: Percentage of medium-risk evaluations.
- `pct_high_risk`: Percentage of high-risk evaluations.
- `total_signals_detected`: Total number of threat signals identified.

### 2. `v_risk_level_distribution`
Provides grouping by risk classification:
- `risk_level`: Assessment category (*Lower detected risk*, *Suspicious*, *High risk*).
- `assessment_count`: Volume of incidents in this category.
- `avg_score`: Average score within this classification.
- `percentage`: Share of total platform volume.

### 3. `v_risk_signal_frequency`
Analyzes prevalence across the 9 standardized risk catalog signals:
- `signal_id`: Unique signal identifier (1 to 9).
- `signal_name`: Technical signal codename (`urgency`, `sensitive_info`, `payment_pressure`, `threats_suspension`, `prize_reward`, `url_insecure_http`, `url_ip_hostname`, `url_punycode`, `url_suspicious_formatting`).
- `category`: Human-readable categorization (e.g., *Credential Harvesting*, *Psychological Pressure*).
- `description`: Plain-English explanation.
- `detection_count`: Frequency of detection across all assessments.
- `prevalence_pct`: Percentage of total assessments where this signal was triggered.

### 4. `v_assessment_trends`
Captures volume and risk progression over time:
- `assessment_date`: ISO formatted date (`YYYY-MM-DD`).
- `total_assessments`: Daily scan count.
- `low_risk_count`: Daily low-risk count.
- `medium_risk_count`: Daily medium-risk count.
- `high_risk_count`: Daily high-risk count.
- `avg_risk_score`: Daily average risk score.

---

## 4. Power BI Connection Methods

Power BI Desktop offers two integration pathways:

### Method 1: Anonymized CSV Import (Recommended for Local / Offline Evaluation)

This method does not require cloud database access and operates 100% offline.

1. **Download Telemetry CSV:**
   - Log into the TRUSTMESH platform with an Administrator account (`admin`).
   - Navigate to the **Admin Console** (`/admin`).
   - Click the green **"Download Anonymized CSV"** button, or issue a request to:
     ```
     GET /api/analytics/export
     ```
   - Save the file as `trustmesh_analytics_export.csv`.

2. **Open Power BI Desktop:**
   - Launch Microsoft Power BI Desktop.
   - On the Home ribbon, click **Get Data** -> **Text/CSV**.
   - Browse to `trustmesh_analytics_export.csv` and click **Open**.

3. **Verify Data Types & Schema:**
   - In the preview window, confirm the detected column types:
     * `Assessment_ID`: Integer (Whole Number)
     * `Assessment_Date`: Date/Time or Date
     * `Input_Type`: Text
     * `Risk_Score`: Integer (Whole Number)
     * `Risk_Classification`: Text
     * `Detected_Signals_Count`: Integer (Whole Number)
     * `Detected_Signal_Names`: Text
     * `Detected_Signal_Categories`: Text
     * `Recommendation`: Text
     * `Engine_Version`: Text
     * `Content_Fingerprint_SHA256`: Text
   - Click **Load** (or **Transform Data** if adjusting date locales).

---

### Method 2: Azure SQL Database Direct Connection (Cloud Mode)

This method connects Power BI directly to the Azure SQL Cloud Database.

1. **Prerequisites:**
   - Ensure the database server firewall allows Power BI access (enable *"Allow Azure services and resources to access this server"* or whitelist your client IP in the Azure Portal).
   - Ensure the database schema has been deployed using `python migrate_to_azure.py`.

2. **Open Power BI Desktop:**
   - Click **Get Data** -> **SQL Server database**.
   - Enter your connection details:
     * **Server:** `<YOUR_SERVER>.database.windows.net` (e.g., `trustmesh-sql-srv.database.windows.net`)
     * **Database:** `trustmesh-db`
     * **Data Connectivity Mode:** Choose between:
       - **Import Mode (Recommended):** Caches a snapshot locally in Power BI, enabling fast performance and full DAX formula support.
       - **DirectQuery Mode:** Queries Azure SQL in real time on every visual interaction, ensuring live updates without manual refresh.
   - Click **OK**.

3. **Authentication:**
   - In the credentials dialog, select **Database**.
   - Enter your `AZURE_SQL_USERNAME` (e.g., `trustmeshadmin`) and `AZURE_SQL_PASSWORD`.
   - Click **Connect**.

4. **Select Analytics Views:**
   - In the Navigator window, expand your database and select:
     * `v_analytics_overview`
     * `v_risk_level_distribution`
     * `v_risk_signal_frequency`
     * `v_assessment_trends`
   - Click **Load**.

---

## 5. Suggested 3-Page Dashboard Design

### Page 1: TRUSTMESH Threat Overview (Executive KPI Dashboard)

*Goal: Immediate situational awareness of platform scam activity.*

| Visual Component | Recommended Chart Type | Fields / Configuration | Purpose |
| :--- | :--- | :--- | :--- |
| **Total Evaluations** | Card Visual | Measure: `[Total Assessments]` | High-level volume indicator |
| **High-Risk Incidents** | Card Visual (Accent: Red) | Measure: `[High-Risk Count]` | Critical threat alert |
| **Suspicious Incidents** | Card Visual (Accent: Amber) | Measure: `[Medium-Risk Count]` | Cautionary threat volume |
| **Lower Risk Scans** | Card Visual (Accent: Green) | Measure: `[Low-Risk Count]` | Safe / baseline volume |
| **Average Threat Score** | Card Visual (Accent: Mint) | Measure: `[Average Risk Score]` | Platform severity benchmark |
| **Risk Category Share** | Donut Chart | Legend: `Risk_Classification`<br>Values: `[Total Assessments]` | Proportional threat distribution |
| **Incident Volume Trend** | Line Chart | X-Axis: `Assessment_Date`<br>Y-Axis: `[Total Assessments]` | Historical evaluation progression |

---

### Page 2: Scam Signal Intelligence (Heuristic Breakdown)

*Goal: Identify which psychological manipulation techniques and deceptive tactics are most prevalent.*

| Visual Component | Recommended Chart Type | Fields / Configuration | Purpose |
| :--- | :--- | :--- | :--- |
| **Heuristic Prevalence** | Clustered Horizontal Bar Chart | Y-Axis: `Detected_Signal_Names`<br>X-Axis: `[Total Detected Signals]` | Ranks the most common scam markers |
| **Tactic Distribution** | Treemap / Pie Chart | Group: `Detected_Signal_Categories`<br>Values: `[Total Detected Signals]` | Groups threats into Psychological Pressure, Financial Solicitation, etc. |
| **Risk Score by Input Type** | Clustered Column Chart | X-Axis: `Input_Type` (message vs. url)<br>Y-Axis: `[Average Risk Score]` | Compares severity of URL attacks versus SMS/email messaging |
| **Detailed Heuristics Matrix** | Table / Matrix Visual | Rows: `Assessment_ID`, `Assessment_Date`, `Risk_Classification`<br>Values: `Detected_Signal_Names`, `Risk_Score` | Granular audit trail for security instructors |

---

### Page 3: Temporal Threat Trend Analysis (Time Series)

*Goal: Track changing risk patterns across days, weeks, and months.*

| Visual Component | Recommended Chart Type | Fields / Configuration | Purpose |
| :--- | :--- | :--- | :--- |
| **Risk Level Over Time** | Stacked Area Chart | X-Axis: `Assessment_Date`<br>Y-Axis: `[Total Assessments]`<br>Legend: `Risk_Classification` | Visualizes surges in malicious activity |
| **Daily Average Severity** | Line Chart with Trendline | X-Axis: `Assessment_Date`<br>Y-Axis: `[Average Risk Score]` | Identifies days with coordinated high-severity campaigns |
| **Weekly Comparison** | Clustered Column Chart | X-Axis: Week Period<br>Y-Axis: `[High-Risk Count]`, `[Medium-Risk Count]` | Periodic reporting for weekly digests |
| **Interactive Date Slicer** | Range Slider Visual | Field: `Assessment_Date` | Filters all visuals to specific review periods |

---

## 6. Official DAX Measures Library

Add these calculated measures in Power BI Desktop to compute KPIs dynamically based on user filters. 

Assuming the dataset table is named `'trustmesh_analytics_export'` (or `'v_analytics_overview'`):

### 1. Total Assessments
```dax
Total Assessments = 
COUNT('trustmesh_analytics_export'[Assessment_ID])
```

### 2. High-Risk Assessments Count
```dax
High-Risk Count = 
CALCULATE(
    COUNT('trustmesh_analytics_export'[Assessment_ID]),
    'trustmesh_analytics_export'[Risk_Classification] = "High risk"
)
```

### 3. Medium-Risk Assessments Count
```dax
Medium-Risk Count = 
CALCULATE(
    COUNT('trustmesh_analytics_export'[Assessment_ID]),
    'trustmesh_analytics_export'[Risk_Classification] = "Suspicious"
)
```

### 4. Low-Risk Assessments Count
```dax
Low-Risk Count = 
CALCULATE(
    COUNT('trustmesh_analytics_export'[Assessment_ID]),
    'trustmesh_analytics_export'[Risk_Classification] = "Lower detected risk"
)
```

### 5. Average Risk Score
```dax
Average Risk Score = 
ROUND(AVERAGE('trustmesh_analytics_export'[Risk_Score]), 1)
```

### 6. High-Risk Percentage
```dax
High-Risk Percentage = 
DIVIDE([High-Risk Count], [Total Assessments], 0) * 100
```

### 7. Total Detected Signals
```dax
Total Detected Signals = 
SUM('trustmesh_analytics_export'[Detected_Signals_Count])
```

### 8. Signals Per Incident Ratio
```dax
Signals Per Assessment = 
DIVIDE([Total Detected Signals], [Total Assessments], 0)
```

---

## 7. Troubleshooting & FAQ

### Q1: Why does Power BI show "Unable to connect" when selecting Azure SQL?
- **Cause:** Azure SQL Database firewall rules are blocking your IP address.
- **Solution:** In the Azure Portal, open your SQL Server -> **Networking** -> add your client IP address to the firewall rules, or enable *"Allow Azure services and resources to access this server"*.

### Q2: How can I refresh the CSV data automatically?
- **Solution:** Place `trustmesh_analytics_export.csv` in a fixed folder on your machine. Whenever you re-download the CSV, replace the existing file and click **Refresh** in Power BI Desktop. All visuals and DAX calculations update immediately.

### Q3: What is the difference between DirectQuery and Import mode?
- **Import Mode:** Imports data into Power BI memory. Fast, responsive, supports full DAX capabilities, and operates offline. Data must be refreshed manually.
- **DirectQuery:** Leaves data in Azure SQL and sends queries on every visual interaction. Ensures live data but requires an active internet connection and is subject to SQL Server response latency.

---

## 8. Verification & Test Evidence

The analytics layer is fully covered by automated regression tests in `test_analytics_powerbi.py`:
- `test_01_analytics_overview_query`: Verified 100% accurate computation of total counts, risk classification volumes, and score averages.
- `test_02_risk_distribution_query`: Verified category breakdown consistency.
- `test_03_risk_signal_frequency_query`: Verified detection count and prevalence across all 9 catalog signals.
- `test_04_trend_queries`: Verified daily, weekly, and monthly trend grouping.
- `test_05_csv_export_generation_and_headers`: Verified CSV syntax and RFC-4180 compatibility.
- `test_06_empty_database_handling`: Verified zero-division safety on empty tables.
- `test_07_admin_authorization_success`: Verified administrative access across all endpoints.
- `test_08_non_admin_access_restrictions`: Verified strict HTTP 403 Forbidden enforcement on unauthorized users.
- `test_09_privacy_guarantees_on_exported_csv`: Verified total exclusion of user credentials and raw content.
- `test_10_sqlite_views_integrity`: Verified that all 4 views execute natively in SQLite.
- `test_11_azure_sql_view_batches_parsed`: Verified that all 4 views parse cleanly as T-SQL batches.
- `test_12_phase_1_to_3_and_task2_task3_intact`: Verified backward compatibility with all prior phases.

