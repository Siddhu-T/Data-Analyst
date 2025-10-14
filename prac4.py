import pandas as pd

# -----------------------------
# 1. Hierarchical Data (MultiIndex)
# -----------------------------

# Create sample hierarchical data
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

# Create a sample DataFrame
data = {
    "Student": ["Amit", "Amit", "Riya", "Riya", "Karan", "Karan"],
    "Subject": ["Math", "Science", "Math", "Science", "Math", "Science"],
    "Marks": [85, 78, 90, 88, 76, 80]
}
df = pd.DataFrame(data)
print("\nOriginal DataFrame:\n", df)

# Pivot the data: Subjects as columns
pivoted = df.pivot(index="Student", columns="Subject", values="Marks")
print("\n--- Pivoted DataFrame ---")
print(pivoted)

