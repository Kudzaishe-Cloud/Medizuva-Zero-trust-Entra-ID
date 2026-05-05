import pandas as pd

# Load the existing personas CSV
df = pd.read_csv(r"C:\Users\Kudzaishe\medizuva-zt-framework\data\personas\medizuva_500_personas.csv")

# Show the wrong domain before fixing
print("Before fix:")
print(df["Email"].head(3).to_string(index=False))

# Replace the wrong domain with your actual Entra tenant domain
df["Email"] = df["Email"].str.replace(
    "medizuva.onmicrosoft.com",
    "micrlabs.onmicrosoft.com"
)

# Save the updated CSV back to the same file
df.to_csv(
    r"C:\Users\Kudzaishe\medizuva-zt-framework\data\personas\medizuva_500_personas.csv",
    index=False
)

print("\nAfter fix:")
print(df["Email"].head(3).to_string(index=False))
print(f"\nAll {len(df)} email addresses updated successfully")