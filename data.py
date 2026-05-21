import pandas as pd
import numpy as np

def generate_dummy_date(n=500):
    np.random.seed(42)

    data = pd.DataFrame({
        "faild_attempts_last_5min": np.random.randint(0,10, n),
        "success_last_hour": np.random.randint(0,5, n),
        "distinct_username_per_ip": np.random.randint(1,5, n),
        "time_between_attempts": np.random.randint(1, 300, n),


    })

    data["is_attack"] = (
        (data["faild_attempts_last_5min"] > 5) |
        (data["time_between_attempts"] < 10)
    ).astype(int)

    return data

if __name__ == "_main_":
    df = generate_dummy_date()
    print(df.head())