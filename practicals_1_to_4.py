Practical 1

Aim: Create one-dimensional data using Series and perform various operations on it.
import pandas as pd
import numpy as np

# Create a one-dimensional Series
data = pd.Series([10, 20, 30, 40, 50, 60, 70])
print("Original Series:")
print(data)

print("\n--- Operations on Series ---")
print("Sum:", data.sum())
print("Mean:", data.mean())
print("Maximum:", data.max())
print("Minimum:", data.min())
print("Standard Deviation:", data.std())
print("Count:", data.count())

# Element-wise operations
print("\nEach element squared:")
print(data ** 2)

Practical 2

Aim: Create Two-dimensional data with the help of DataFrames and perform different operations on it.
import pandas as pd

# Create a two-dimensional DataFrame
data = {
    'Math': [85, 90, 76, 95, 65],
    'Science': [78, 88, 80, 92, 70],
    'English': [82, 85, 78, 90, 72]
}
students = ['Amit', 'Riya', 'Karan', 'Simran', 'Arjun']

df = pd.DataFrame(data, index=students)
print("Original DataFrame:")
print(df)

# Column-wise operations
print("\n--- Column-wise Operations ---")
print("Average Marks (per subject):")
print(df.mean())

print("\nMaximum Marks (per subject):")
print(df.max())

print("\nMinimum Marks (per subject):")
print(df.min())

# Row-wise operations
print("\n--- Row-wise Operations ---")
df['Total'] = df.sum(axis=1)
df['Average'] = df.mean(axis=1)
print(df)

# Conditional operation
df['Result'] = df['Average'].apply(lambda x: "Pass" if x >= 50 else "Fail")
print("\nWith Result column:")
print(df)


Practical 3

Aim: Read data from different file formats (JSON, HTML, XML, CSV) and handle missing data and outliers.
import pandas as pd
import numpy as np

# ------------------------
# 1. Reading Different File Formats
# ------------------------

# CSV file
csv_df = pd.read_csv("DV prac/data.csv")
print("CSV Data:\n", csv_df.head())

# JSON file
json_df = pd.read_json("DV prac/data.json")
print("\nJSON Data:\n", json_df.head())

# HTML file
html_dfs = pd.read_html("DV prac/data.html")  # returns list of DataFrames
html_df = html_dfs[0]  # take first table
print("\nHTML Data:\n", html_df.head())

# XML file
xml_df = pd.read_xml("DV prac/data.xml")
print("\nXML Data:\n", xml_df.head())

# ------------------------
# 2. Check for Missing Data
# ------------------------
print("\n--- Missing Data Check ---")
print(csv_df.isnull().sum())   # missing values in CSV
print(json_df.isnull().sum())  # missing values in JSON

# Handle missing values
csv_df.fillna(csv_df.mean(numeric_only=True), inplace=True)
json_df.dropna(inplace=True)

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
for col in csv_df.select_dtypes(include=np.number).columns:
    Q1 = csv_df[col].quantile(0.25)
    Q3 = csv_df[col].quantile(0.75)
    IQR = Q3 - Q1
    lower_bound = Q1 - 1.5 * IQR
    upper_bound = Q3 + 1.5 * IQR
    csv_df[col] = np.where(csv_df[col] < lower_bound, lower_bound, csv_df[col])
    csv_df[col] = np.where(csv_df[col] > upper_bound, upper_bound, csv_df[col])

print("\nData after handling missing values and outliers:\n", csv_df.head())


Practical 4

Aim: Perform reshaping of hierarchical data and pivoting DataFrame data.
import pandas as pd

# -----------------------------
# 1. Hierarchical Data (MultiIndex)
# -----------------------------

arrays = [
    ["Class A", "Class A", "Class A", "Class B", "Class B", "Class B"],
    ["Math", "Science", "English", "Math", "Science", "English"]
]
index = pd.MultiIndex.from_arrays(arrays, names=("Class", "Subject"))
data = [85, 90, 78, 88, 82, 95]

df_hier = pd.DataFrame({"Marks": data}, index=index)
print("Original Hierarchical Data:\n", df_hier)

# Reshape using unstack
print("\n--- Reshaping (Unstack) ---")
reshaped = df_hier.unstack(level="Subject")
print(reshaped)

# -----------------------------
# 2. Pivoting DataFrame
# -----------------------------
data = {
    "Student": ["Amit", "Amit", "Riya", "Riya", "Karan", "Karan"],
    "Subject": ["Math", "Science", "Math", "Science", "Math", "Science"],
    "Marks": [85, 78, 90, 88, 76, 80]
}
df = pd.DataFrame(data)
print("\nOriginal DataFrame:\n", df)

# Pivot the data
pivoted = df.pivot(index="Student", columns="Subject", values="Marks")
print("\n--- Pivoted DataFrame ---")
print(pivoted)
