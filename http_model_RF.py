import numpy as np
import pandas as pd
from sklearn.model_selection import cross_val_score, StratifiedKFold, train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import requests

from label import preprocess_data


def load_and_combine_datasets():

    df_combined = pd.read_csv('http_preprocessed_data.csv')
    print("Dataset Sample:")
    print(df_combined.head())
    df_combined['Compliant'] = df_combined['Compliant'].map({True: 1, False: 0})
    print("\nDataset Summary:")
    print("Total Samples:", len(df_combined))
    return df_combined

def model_evaluation(X, y):

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    clf = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight='balanced'
    )
    cv_scores = cross_val_score(clf, X, y, cv=cv, scoring='accuracy')
    print("\nCross-Validation Scores:")
    print(cv_scores)
    print("Mean CV Accuracy: {:.2f}% (+/- {:.2f}%)".format(
        cv_scores.mean() * 100,
        cv_scores.std() * 2 * 100
    ))
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    print("\nTest Set Performance:")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))

    return clf


def test_http_request(model, label_encoders, feature_columns, url): #Test on live http request on the nginx servber setup at 192.168.1.106

    try:
        response = requests.get(url, verify=False)
        packet_data = {
            "HTTP Version": f"HTTP/{response.raw.version // 10}.{response.raw.version % 10}",
            "HSTS": "Strict-Transport-Security" in response.headers,
            "CSP": response.headers.get("Content-Security-Policy", "none").split(';')[0],
            "Compression": response.headers.get("Content-Encoding", "none"),
            "XFrame-Options": response.headers.get("X-Frame-Options", ""),
        }
        print(response.headers)
        print(packet_data)
        packet_df = pd.DataFrame([packet_data])

        for col in label_encoders.keys():
            if col in packet_df.columns:
                if packet_df[col].isnull().any():
                    packet_df[col].fillna(label_encoders[col].classes_[0], inplace=True)
                packet_df[col] = packet_df[col].apply(
                    lambda x: x if x in label_encoders[col].classes_ else "unknown"
                )
                if "unknown" not in label_encoders[col].classes_:
                    label_encoders[col].classes_ = np.append(label_encoders[col].classes_, "unknown")
                packet_df[col] = packet_df[col].map(
                    lambda x: list(label_encoders[col].classes_).index(x)
                )

        for col in feature_columns:
            if col not in packet_df.columns:
                packet_df[col] = 0

        X_packet = packet_df[feature_columns]

        compliance_prediction = model.predict(X_packet)[0]
        return "Compliant" if compliance_prediction == 1 else "Non-compliant"

    except Exception as e:
        print(f"Error during HTTP request: {e}")
        return None


def main():
    try:
        df_combined = load_and_combine_datasets()
        X, y, label_encoders, feature_columns = preprocess_data(df_combined)
        model = model_evaluation(X, y)
        nginx_ip = "https://192.168.1.106"
        print("\nTesting Live HTTP Request:")
        result = test_http_request(model, label_encoders, feature_columns, nginx_ip)
        print(f"Prediction for {nginx_ip}: {result}")
    except Exception as e:
        print(f"An error occurred: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
