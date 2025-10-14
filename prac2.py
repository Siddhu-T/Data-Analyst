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
