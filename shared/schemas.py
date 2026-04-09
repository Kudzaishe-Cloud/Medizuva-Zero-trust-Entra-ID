# shared/schemas.py
# ============================================================
# Shared reference data used across all pillars.
# All values here are factual and verifiable.
# ============================================================

# LOCATIONS defines the 5 Zimbabwean cities where MediZuva operates.
# "lat" and "lon" are real GPS coordinates for each city centre.
# They are verifiable via any public mapping service (e.g. Google Maps,
# OpenStreetMap). "weight" is the fraction of staff assigned to each city
# and must sum to 1.0.
LOCATIONS = {
    "Harare":   {"lat": -17.8292, "lon": 31.0522, "weight": 0.50},
    "Bulawayo": {"lat": -20.1325, "lon": 28.6264, "weight": 0.20},
    "Mutare":   {"lat": -18.9707, "lon": 32.6709, "weight": 0.10},
    "Gweru":    {"lat": -19.4500, "lon": 29.8167, "weight": 0.10},
    "Masvingo": {"lat": -20.0744, "lon": 30.8328, "weight": 0.10},
}
