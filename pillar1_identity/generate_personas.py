# generate_personas.py
# ============================================================
# PURPOSE: Generate 500 synthetic MediZuva healthcare staff personas
# and save them as a CSV file that every other pillar reads from.
# ============================================================

# sys and os are built-in Python modules for system operations
# sys.path.append tells Python where to look for the shared/ folder
import sys, os, random
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

# Faker is a library that generates realistic fake data
# We use it specifically for generating realistic hire dates
from faker import Faker

# pandas is a library for working with tabular data (like spreadsheets)
# We use it to organise all 500 persona records and save them as a CSV
import pandas as pd

# datetime gives us the current date and time for the CreatedDate field
from datetime import datetime

# Import our shared data — department config, locations, and names
# This is why schemas.py must exist before running this script
from shared.schemas import DEPARTMENT_CONFIG, LOCATIONS, FIRST_NAMES, SURNAMES

# Create a Faker instance for generating dates
fake = Faker()

# random.seed(42) makes the random choices reproducible
# This means running the script twice always produces identical output
# Important for academic work — your supervisor can verify your results
random.seed(42)


def generate_persona(dept, title, emp_num):
    """
    Build a single persona dictionary for one MediZuva employee.
    dept     = the department they belong to (e.g. "Clinical")
    title    = their job title (e.g. "Doctor")
    emp_num  = their unique employee number (1 to 500)
    """

    # Randomly pick a language group (Shona or Ndebele) then pick a name
    lang  = random.choice(list(FIRST_NAMES.keys()))
    first = random.choice(FIRST_NAMES[lang])
    last  = random.choice(SURNAMES)

    # Pick a city based on weighted probability
    # random.choices with weights means Harare is picked ~50% of the time
    loc = random.choices(
        list(LOCATIONS.keys()),
        weights=[v["weight"] for v in LOCATIONS.values()]
    )[0]

    # Return a dictionary representing one complete employee record
    # Every key here becomes a column in the final CSV file
    return {
        # Unique employee ID formatted as MZ0001 through MZ0500
        "EmployeeID":      f"MZ{emp_num:04d}",

        "FirstName":       first,
        "LastName":        last,

        # Email uses the Entra ID tenant domain so it matches the real account
        "Email":           f"{first.lower()}.{last.lower()}{emp_num}@medizuva.onmicrosoft.com",

        "Department":      dept,
        "JobTitle":        title,
        "Location":        loc,

        # Add small random variation to GPS coordinates
        # so personas in the same city are not all at the exact same point
        "Latitude":        round(LOCATIONS[loc]["lat"] + random.uniform(-0.05, 0.05), 4),
        "Longitude":       round(LOCATIONS[loc]["lon"] + random.uniform(-0.05, 0.05), 4),

        # RiskScore starts low (5-20). The HIBP pipeline in Pillar 4
        # will raise this to 80+ for exposed accounts automatically
        "RiskScore":       random.randint(5, 20),

        # 70% of staff have compliant (managed, encrypted) devices
        # 30% do not — these will be challenged or blocked by Conditional Access
        "DeviceCompliant": random.choices([True, False], weights=[0.70, 0.30])[0],

        # 85% have registered for MFA (multi-factor authentication)
        # 15% have not — this is a security gap your policies will address
        "MFARegistered":   random.choices([True, False], weights=[0.85, 0.15])[0],

        # All accounts start as Active — the leaver script changes this to Disabled
        "AccountStatus":   "Active",

        # These two fields start as False/0 — the HIBP pipeline updates them
        "HIBPExposed":     False,
        "HIBPBreachCount": 0,

        # Random hire date between 5 years ago and 30 days ago
        # No one was hired in the last 30 days to keep the data realistic
        "HireDate":        fake.date_between("-5y", "-30d").isoformat(),

        # Record when this persona was generated
        "CreatedDate":     datetime.now().isoformat()
    }


# Build the full list of 500 personas by looping through each department
rows = []   # empty list — we will fill this with 500 dictionaries
n    = 1    # employee number counter, starts at 1

for dept, cfg in DEPARTMENT_CONFIG.items():
    # cfg["count"] tells us how many staff to create for this department
    for _ in range(cfg["count"]):
        # Pick a random job title from this department's title list
        title = random.choice(cfg["titles"])

        # Generate one persona and add it to our list
        rows.append(generate_persona(dept, title, n))
        n += 1  # increment the employee number

# Convert the list of dictionaries into a pandas DataFrame (like a spreadsheet)
df = pd.DataFrame(rows)

# Create the data/personas/ folder if it does not already exist
# exist_ok=True means it will not error if the folder already exists
os.makedirs("../data/personas", exist_ok=True)

# Save the DataFrame as a CSV file
# index=False means do not add an extra row-number column
df.to_csv("../data/personas/medizuva_500_personas.csv", index=False)

# Print a summary so you can confirm it ran correctly
print(f"Generated {len(df)} personas")
print("\nDepartment breakdown:")
print(df["Department"].value_counts().to_string())
print("\nFirst 3 email addresses generated:")
print(df["Email"].head(3).to_string(index=False))
print("\nCSV saved to: ../data/personas/medizuva_500_personas.csv")