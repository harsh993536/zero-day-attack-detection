def calculate_risk_score(anomaly_score):
    """
    Convert Isolation Forest anomaly score
    into a 0-100 risk score.
    """

    # Isolation Forest decision scores:
    # Higher = more normal
    # Lower = more anomalous

    risk = (0.5 - anomaly_score) * 200

    # Keep score between 0 and 100
    risk = max(0, min(100, risk))

    return round(risk, 2)


def get_risk_level(risk_score):

    if risk_score < 30:
        return "LOW"

    elif risk_score < 70:
        return "MEDIUM"

    else:
        return "HIGH"



if __name__ == "__main__":

    test_scores = [
        0.4,
        0.2,
        0.0,
        -0.2
    ]

    print("Risk Score Testing\n")

    for score in test_scores:

        risk = calculate_risk_score(score)
        level = get_risk_level(risk)

        print(
            f"Anomaly Score: {score:.2f} | "
            f"Risk Score: {risk} | "
            f"Risk Level: {level}"
        )