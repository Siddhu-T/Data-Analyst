import pandas as pd
import numpy as np

# ------------------------
# 1. Reading Different File Formats
# ------------------------

# CSV file
csv_df = pd.read_csv("DV prac\data.csv")
print("CSV Data:\n", csv_df.head())

# JSON file
json_df = pd.read_json("DV prac\data.json")
print("\nJSON Data:\n", json_df.head())

# HTML file (reads tables from HTML page)
html_dfs = pd.read_html("DV prac\data.html")   # returns list of DataFrames
html_df = html_dfs[0]                  # take first table
print("\nHTML Data:\n", html_df.head())

# XML file
xml_df = pd.read_xml("DV prac\data.xml")
print("\nXML Data:\n", xml_df.head())


# ------------------------
# 2. Check for Missing Data
# ------------------------
print("\n--- Missing Data Check ---")
print(csv_df.isnull().sum())   # number of missing values in CSV
print(json_df.isnull().sum())  # number of missing values in JSON

# Handle missing values
csv_df.fillna(csv_df.mean(numeric_only=True), inplace=True)  # replace with mean
json_df.dropna(inplace=True)  # drop rows with missing values


# ------------------------
# 3. Detect Outliers
# ------------------------
def detect_outliers(df, col):
    """Detect outliers using IQR method"""
    Q1 = df[col].quantile(0.25)
    Q3 = df[col].quantile(0.75)
    IQR = Q3 - Q1
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    outliers = df[(df[col] < lower_bound) | (df[col] > upper_bound)]
    return outliers


# ------------------------
# 4. Handle Outliers
# ------------------------
# Example: Cap outliers within bounds
for col in csv_df.select_dtypes(include=np.number).columns:
    Q1 = csv_df[col].quantile(0.25)
    Q3 = csv_df[col].quantile(0.75)
    IQR = Q3 - Q1
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    csv_df[col] = np.where(csv_df[col] < lower_bound, lower_bound, csv_df[col])
    csv_df[col] = np.where(csv_df[col] > upper_bound, upper_bound, csv_df[col])

print("\nData after handling missing values and outliers:\n", csv_df.head())
