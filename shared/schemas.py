# shared/schemas.py
# ============================================================
# This file is the single source of truth for all shared data.
# Every script in every pillar imports from here.
# NEVER rename these variables without telling the whole team.
# ============================================================

# DEPARTMENT_CONFIG defines the 6 departments at MediZuva.
# "count" tells the persona generator how many staff to create per dept.
# "titles" is the list of job titles available in that department.
# Total must add up to 500: 200+100+120+30+30+20 = 500
DEPARTMENT_CONFIG = {
    "Clinical":   {"count": 200, "titles": ["Doctor", "Nurse", "Lab Technician", "Radiologist"]},
    "Billing":    {"count": 100, "titles": ["Billing Clerk", "Claims Analyst", "Finance Officer", "Medical Coder"]},
    "Operations": {"count": 120, "titles": ["HR Manager", "Receptionist", "Facilities Manager", "Administrator"]},
    "IT":         {"count":  30, "titles": ["IT Administrator", "Help Desk", "Security Analyst", "Network Engineer"]},
    "Pharmacy":   {"count":  30, "titles": ["Pharmacist", "Pharmacy Technician"]},
    "Radiology":  {"count":  20, "titles": ["Radiologist", "Radiographer"]}
}

# LOCATIONS defines the 5 Zimbabwean cities where MediZuva operates.
# "lat" and "lon" are GPS coordinates — used later for geographic analysis.
# "weight" controls how likely a persona is assigned to that city.
# Harare gets 0.50 (50%) because it is the capital and largest office.
# All weights must add up to 1.0: 0.50+0.20+0.10+0.10+0.10 = 1.0
LOCATIONS = {
    "Harare":   {"lat": -17.8292, "lon": 31.0522, "weight": 0.50},
    "Bulawayo": {"lat": -20.1325, "lon": 28.6264, "weight": 0.20},
    "Mutare":   {"lat": -18.9707, "lon": 32.6709, "weight": 0.10},
    "Gweru":    {"lat": -19.4500, "lon": 29.8167, "weight": 0.10},
    "Masvingo": {"lat": -20.0744, "lon": 30.8328, "weight": 0.10}
}

# FIRST_NAMES contains authentic Zimbabwean first names split by language.
# "shona" names are from the Shona ethnic group (majority in Zimbabwe).
# "ndebele" names are from the Ndebele ethnic group (mainly Bulawayo region).
# The generator randomly picks a language group then picks a name from it.
# This gives the personas realistic cultural diversity.
FIRST_NAMES = {
    "shona":   ["Tatenda", "Chiedza", "Farai", "Tinashe", "Rudo", "Takudzwa",
                "Munyaradzi", "Nyasha", "Simba", "Tsitsi", "Tendai", "Kudzai"],
    "ndebele": ["Nkosi", "Sibusiso", "Nomvula", "Bongani", "Thandi",
                "Lungelo", "Sifiso", "Nompilo", "Zanele"]
}

# SURNAMES is a flat list of common Zimbabwean family names.
# The generator picks one randomly for each persona.
SURNAMES = [
    "Moyo", "Ncube", "Dube", "Mpofu", "Chikwanda", "Mutasa",
    "Zimba", "Banda", "Phiri", "Sithole", "Chirwa", "Tembo",
    "Nkomo", "Mhlanga", "Gumbo"
]