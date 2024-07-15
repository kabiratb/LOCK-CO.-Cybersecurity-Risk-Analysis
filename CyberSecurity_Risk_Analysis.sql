--CREATE TABLE FOR network_logs
CREATE TABLE network_logs(
		ID SERIAL PRIMARY KEY,
		Source_IP INET NOT NULL,
		Destination_IP INET  NOT NULL,
		Protocol VARCHAR (10) NOT NULL,
		Timestamp TIMESTAMP NOT NULL,
		Traffic_Type VARCHAR(10) NOT NULL,
		Source_Port INT NOT NULL,
		Destination_Port INT NOT  NULL,
		Data_Volume INT NOT NULL,
		Packet_Size INT NOT NULL,
		HTTP_Status_Code INT NOT NULL,
		Firewall_Rule VARCHAR(20) NOT NULL,
		VPN_Status BOOLEAN NOT NULL,
		MFA_Status VARCHAR(10) NOT NULL,
		Credential_Used VARCHAR(50) NOT NULL,
		Data_CLassification VARCHAR(20) NOT NULL,
		Encryption_Algorithm  VARCHAR(50)
);

--CREATE TABLE FOR network_logs_2
CREATE TABLE network_logs_2(
	 Linked_ID INT PRIMARY KEY,
	 Threat_Type VARCHAR(255),
	 Connection_Status VARCHAR(50),
	 Severity_Level VARCHAR(50),
	 Flagged  BOOLEAN,
	 Device_Type VARCHAR(255),
	 Application VARCHAR(255),
	 External_Internal_Flag VARCHAR(50),
	 Service_Name VARCHAR(255),
	 File_Hash VARCHAR(255),
	 Linked_Events_ID UUID,
	 Data_Exflitration_Flag  BOOLEAN,
	 Asset_Classification VARCHAR(255),
	 Session_ID UUID,
	 TTL_Value INT,
	 User_Behaviour_Score FLOAT,
	 Incient_Category VARCHAR(255),
	 Cloud_Service_Info VARCHAR(255),
	 Ioc_Flag BOOLEAN
);

--CREATE TABLE FOR user_activity
CREATE TABLE user_activity(
	ID SERIAL PRIMARY KEY,
	Activity_Count INT,
	Suspicious_Activity BOOLEAN,
	Last_Activity_Timestamp TIMESTAMP,
	Browser TEXT,
	Number_of_Downloads INT,
	Email_Sent INT
);

SELECT * FROM user_activity
LIMIT 5;

--Checking and removing duplicated
SELECT source_ip, destination_ip, protocol, COUNT(*)
FROM network_logs
GROUP BY 1,2,3  -- this is to specify the columns called without aggregate functions
HAVING COUNT(*) >1; 

SELECT linked_id, threat_type, severity_level, device_type, COUNT(*) AS No_of_Record
FROM network_logs_2
GROUP BY 1,2,3,4 --linked_id, threat_type, severity_level, device_type
HAVING COUNT(*) > 1;

SELECT * FROM network_logs_2;


--Checking and deleting null Values in all column
--To cross check the data quality
SELECT 
	COUNT(CASE WHEN source_ip IS NULL THEN 1 END) AS Source_IP_Missing,
	COUNT(CASE WHEN destination_ip IS NULL THEN 1 END) AS Destination_IP_Missing,
	COUNT(CASE WHEN protocol IS NULL THEN 1 END) AS Protocol_Missing,
	COUNT(CASE WHEN timestamp IS NULL THEN 1 END) AS Timestamp_Missing,
	COUNT(CASE WHEN traffic_type IS NULL THEN 1 END) AS Traffic_Type_Missing,
	COUNT(CASE WHEN source_port IS NULL THEN 1 END) AS Source_Port_Missing,
	COUNT(CASE WHEN destination_port IS NULL THEN 1 END) AS Destination_Port_Missing,
	COUNT(CASE WHEN data_volume IS NULL THEN 1 END) AS Data_Volume_Missing,
	COUNT(CASE WHEN packet_size IS NULL THEN 1 END) AS Packet_Size_Missing,
	COUNT(CASE WHEN http_status_code IS NULL THEN 1 END) AS Http_Status_Code_Missing,
	COUNT(CASE WHEN firewall_rule IS NULL THEN 1 END) AS Firewall_rule_Missing,
	COUNT(CASE WHEN vpn_status IS NULL THEN 1 END) AS Vpn_Status_Missing,
	COUNT(CASE WHEN mfa_status IS NULL THEN 1 END) AS Mfa_Status_Missing,
	COUNT(CASE WHEN credential_used IS NULL THEN 1 END) AS Credential_Used_Missing,
	COUNT(CASE WHEN data_classification IS NULL THEN 1 END) AS Data_Classification_Missing,
	COUNT(CASE WHEN Encryption_Algorithm IS NULL THEN 1 END) AS Encrytion_Algorithm_Missing
From network_logs;	


--To discover if the null value in encryption_algorithm has other vital information
Select * from network_logs
Where encryption_algorithm IS NULL;

--UPDATE network_logs , encryption_algorithm NULL to UNKNOWN
UPDATE network_logs
SET encryption_algorithm = 'Unknown'
WHERE encryption_algorithm IS NULL;

--CHECK IF THE UPDATE IS FIX TO BE SURE THERE IS KNOW NULL 
SELECT
	COUNT(CASE WHEN n.encryption_algorithm IS NULL THEN 1 END) AS Encyption_Algorithm_Missing
FROM network_logs n;	

SELECT traffic_type, traffic_category
FROM network_logs
Limit 10;

ALTER TABLE network_logs ADD COLUMN Traffic_Category VARCHAR(255);

UPDATE network_logs
SET traffic_category = CASE WHEN traffic_type = 'Inbound' THEN 'Incoming' ELSE 'Outgoing' END;

--Alter network_logs_2 to add severity category
ALTER TABLE network_logs_2 ADD COLUMN Severity_category VARCHAR(255);
UPDATE network_logs_2 
SET severity_category = 
		CASE 
			 WHEN severity_level = 'Low' THEN 'Low Risk'
			 WHEN severity_level = 'Medium' THEN 'Medium Risk'
			 WHEN severity_level = 'Critical' THEN 'Critical Risk'
			 ELSE 'High Risk'
		 END;



SELECT severity_category
FROM network_logs_2
LIMIT 10;

--COUNT THE number of Severity levels
SELECT severity_level, severity_category, COUNT(*) AS "Total_Severity"
FROM network_logs_2
Group BY severity_level, severity_category
Order by 3 desc;  --3 indicate the third column which is total_severity

SELECT 
	SUM(CASE WHEN severity_category = 'High Risk' 	  THEN 1 ELSE 0 END) AS High_Risk_Count,
	SUM(CASE WHEN severity_category = 'Medium Risk'   THEN 1 ELSE 0 END) AS Medium_Risk_Count,
	SUM(CASE WHEN severity_category = 'Low Risk' 	  THEN 1 ELSE 0 END) AS Low_Risk_Count,
	SUM(CASE WHEN severity_category = 'Critical Risk' THEN 1 ELSE 0 END) AS Critical_Risk_Count
FROM network_logs_2;	

SELECT severity_category, COUNT(*) AS Total_Count
FROM network_logs_2 
WHERE severity_category IN ('High Risk', 'Medium Risk', 'Low Risk', 'Critical Risk')
GROUP BY severity_category
ORDER BY Total_Count DESC;


--Display the most frequent device used to login
SELECT device_type, COUNT(*) AS No_Of_Device
FROM network_logs_2
GROUP BY device_type
ORDER BY 2 desc;

--Identify the type of traffic with the most data volume
SELECT traffic_category, SUM(data_volume) AS Total_Data_Volume
FROM network_logs
GROUP BY traffic_category
ORDER BY 2 desc;

--Identify the correlation between traffic_type and data volume
SELECT traffic_type, ROUND(AVG(data_volume),2) AS AVG_data_volume
FROM network_logs
GROUP BY traffic_type
ORDER BY AVG_data_volume desc;

--Identify No of flagged threats that where critical
SELECT COUNT(*) AS Flagged_and_Critical
FROM network_logs_2
WHERE flagged = True and asset_classification = 'Critical';

SELECT threat_type, severity_category, flagged, COUNT(*) AS No_Of_Threat
FROM network_logs_2
WHERE flagged = true AND severity_category = 'Critical Risk'
GROUP BY 1,2,3
ORDER BY 4 Desc;

--Determine the encryption algorithm used for sensitive data
SELECT DISTINCT(encryption_algorithm), COUNT(*) AS No_Of_Encryption
FROM network_logs
WHERE data_classification = 'Confidential'
GROUP BY encryption_algorithm
ORDER BY No_Of_Encryption desc;

--Number of Failed cyber attempt
SELECT source_ip, mfa_status, COUNT(id) AS Failed_attempt,
array_agg(DISTINCT firewall_rule) AS Firewall_rule,
array_agg(DISTINCT data_classification) AS Data_classification_type
FROM network_logs
WHERE mfa_status = 'Failed'
GROUP BY 1,2
ORDER BY Failed_attempt desc;


--Count through logs where severity level is critical or high
SELECT COUNT(*)
FROM network_logs n
JOIN network_logs_2 l ON n.id = l.linked_id
WHERE l.severity_level IN ('High', 'Critical');

--Investigate High-Risk and critical incidents
SELECT n.id, n.source_ip, n.destination_ip, n.protocol, l.threat_type, l.severity_level, n.data_classification
FROM network_logs n
JOIN network_logs_2 l ON n.id = l.linked_id
WHERE l.severity_level IN ('High', 'Critical')
ORDER BY l.severity_level DESC;



--CHECK for Type of threat and severity level
SELECT *
FROM network_logs_2
WHERE threat_type IN('DDoS', 'Malware')
ORDER BY severity_level Desc;

--Monitoring data exflitration where data classification meand confidential
SELECT n.*, l.data_exflitration_flag
FROM network_logs n
JOIN network_logs_2 l ON n.id = l.linked_id
WHERE n.data_classification IN ('Confidential', 'Highly Confidential')
AND l.data_exflitration_flag = '1';

--Trend of Diff severity level over time
SELECT l.severity_level, to_char(n.timestamp, 'YYYY-MM') AS Month, --to_char is use to convert timestamp to string text format
COUNT(*) AS Event_count
FROM network_logs n
JOIN network_logs_2 l ON n.id = l.linked_id
GROUP BY l.severity_level, Month
ORDER BY Month ASC, Event_count Desc;

--Count of MFA attempts within a time window
SELECT source_ip, COUNT(id) AS failed_attempt
FROM network_logs
WHERE mfa_status = 'Failed' AND timestamp BETWEEN '2023-01-01' AND '2023-02-01'
GROUP BY source_ip
ORDER BY 2 DESC;

--Threat with high behavouir Score
SELECT l.threat_type, l.user_behaviour_score
FROM network_logs_2 l
JOIN user_activity u ON l.linked_id = u.id
WHERE l.user_behaviour_score > 0.8
ORDER BY l.user_behaviour_score;

--User with multiple download
SELECT *
FROM user_activity
WHERE number_of_downloads > 5 AND activity_count > 50;


--Firewall rule effectiveness
SELECT firewall_rule, COUNT(*) AS rule_trigger_count
FROM network_logs
GROUP BY firewall_rule
ORDER By 2 DESC;

--AVG user behaviour score of different threat_type
SELECT l.threat_type, AVG(l.user_behaviour_score) AS Avg_behaviour
FROM network_logs n
JOIN network_logs_2 l ON n.id = l.linked_id
GROUP BY l.threat_type
ORDER BY 2;

--Trend of High or critical threat by protocol and months
CREATE OR REPLACE FUNCTION fetch_critical_high_trend()
RETURNS TABLE(Month TIMESTAMP, protocol TEXT, critical_high_count INT) AS $$
BEGIN
	RETURN QUERY
		SELECT DATE_TRUNC('month', n.timestamp) AS Month, n.protocol::TEXT,
		COUNT(*)::INT AS critical_high_count
FROM network_logs n
JOIN network_logs_2 l ON n.id = l.linked_id
WHERE l.severity_level IN ('Hight', 'Critical')
GROUP BY DATE_TRUNC('month', n.timestamp), n.protocol
ORDER BY Month, critical_high_count DESC;
END;
$$ LANGUAGE 'plpgsql';
		
SELECT *  FROM fetch_critical_high_trend();  -- TO view the function

--To delete function
--DROP FUNCTION IF EXISTS fetch_critical_high_trend(); --Used to drop and delete functions

--MFA and VPN Status for high or Critical Threats
CREATE OR REPLACE FUNCTION fetch_high_critical_MFA_VPN()
RETURNS TABLE(ID INT, mfa_status TEXT, vpn_status BOOLEAN) AS $$
BEGIN
	RETURN QUERY
	SELECT n.id, n.mfa_status::TEXT, n.vpn_status
	FROM network_logs n
	JOIN network_logs_2 l ON n.id = l.linked_id
	WHERE l.severity_level IN ('High', 'Critical');
END;
$$ LANGUAGE 'plpgsql';

SELECT * FROM fetch_high_critical_MFA_VPN();

--Frequency of different Encryption algorithm for confidential data
CREATE OR REPLACE FUNCTION fetch_encryption_frequency()
RETURNS TABLE(encryption_algorithm TEXT, frequency INT) AS $$
BEGIN
	RETURN QUERY
	SELECT n.encryption_algorithm::TEXT, COUNT(*)::INT
	FROM network_logs AS n
	WHERE n.data_classification = 'Confidential'
	GROUP BY n.encryption_algorithm;
END;
$$ LANGUAGE 'plpgsql';

DROP FUNCTION IF EXISTS fetch_encryption_frequency(); --there was an error so i drop the function to correct it and recreate the function

SELECT * FROM fetch_encryption_frequency();


--Correlation Between Threat type and data classificaion
SELECT l.threat_type, n.data_classification, COUNT(*) AS Incident_Count
FROM network_logs_2 l
JOIN network_logs n ON n.id = l.linked_id
GROUP BY 1,2
ORDER BY Incident_Count desc;

--Incident Distribution By Service
SELECT service_name, COUNT(*) AS Incident_Count
FROM network_logs_2
GROUP BY service_name
ORDER BY 2 desc;

--Browser Analysis of suspicious activities
SELECT browser, suspicious_activity, COUNT(*) AS Browser_Count
FROM user_activity
WHERE suspicious_activity = true
GROUP BY browser, suspicious_activity
ORDER BY Browser_Count desc;




