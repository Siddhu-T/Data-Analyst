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
