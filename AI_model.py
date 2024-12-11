import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
import joblib
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve

class TLSDataPreprocessor:
    def __init__(self):
        self.encoders = {
            'protocol_version': LabelEncoder(),
            'cipher_suite': LabelEncoder(),
            'forward_secrecy': LabelEncoder(),
            'signature_algorithm': LabelEncoder()
        }
        
    def fit_transform(self, df):
        """Fit and transform the data"""
        data = df.copy()
        for column, encoder in self.encoders.items():
            data[column] = encoder.fit_transform(data[column])
        return data
    
    def transform(self, df):
        """Transform new data using fitted encoders"""
        data = df.copy()
        for column, encoder in self.encoders.items():
            data[column] = encoder.transform(data[column])
        return data

class TLSComplianceClassifier:
    def __init__(self, classifier_type='rf', random_state=42):
        """
        Initialize the classifier.
        
        Parameters:
        classifier_type (str): 'rf' for Random Forest or 'lr' for Logistic Regression
        """
        self.classifier_type = classifier_type
        if classifier_type == 'rf':
            self.model = RandomForestClassifier(
                n_estimators=100,
                random_state=random_state,
                n_jobs=-1,
                class_weight='balanced'
            )
        else:
            self.model = LogisticRegression(
                random_state=random_state,
                max_iter=1000,
                class_weight='balanced'
            )
        self.feature_importance = None
        
    def create_compliance_labels(self, data):
        """Create compliance labels based on TLS security criteria"""
        compliant = (
            (data['protocol_version'] == 1) &  # TLS 1.3 (0x0304)
            (data['forward_secrecy'] == 1) &   # Forward secrecy enabled
            (data['certificate_key_length'] >= 2048)  # Minimum key length
        )
        return compliant.astype(int)
    
    def fit(self, X, manual_labels=None):
        """Train the classifier"""
        if manual_labels is not None:
            y = manual_labels
        else:
            y = self.create_compliance_labels(X)
            
        self.model.fit(X, y)
        
        if self.classifier_type == 'rf':
            self.feature_importance = pd.Series(
                self.model.feature_importances_,
                index=X.columns,
                name='Feature Importance'
            ).sort_values(ascending=False)
        else:
            self.feature_importance = pd.Series(
                self.model.coef_[0],
                index=X.columns,
                name='Feature Importance'
            ).sort_values(ascending=False)
        
        return self
    
    def predict(self, X):
        """Make predictions"""
        return self.model.predict(X)
    
    def predict_proba(self, X):
        """Get probability estimates"""
        return self.model.predict_proba(X)
    
    def get_feature_importance(self):
        """Get feature importance ranking"""
        return self.feature_importance

def compare_models(training_data_path, testing_data_path):
    """
    Compare Random Forest and Logistic Regression models.
    
    Parameters:
    training_data_path: Path to training dataset CSV
    testing_data_path: Path to testing dataset CSV
    """
    # Load datasets
    train_df = pd.read_csv(training_data_path)
    test_df = pd.read_csv(testing_data_path)
    
    # Initialize preprocessor
    preprocessor = TLSDataPreprocessor()
    
    # Preprocess training data
    train_processed = preprocessor.fit_transform(train_df)
    
    # Preprocess testing data using the same encoders
    test_processed = preprocessor.transform(test_df)
    
    # Create feature matrices
    features = ['protocol_version', 'cipher_suite', 'forward_secrecy', 
                'signature_algorithm', 'certificate_key_length']
    X_train = train_processed[features]
    X_test = test_processed[features]
    
    # Initialize classifiers
    rf_classifier = TLSComplianceClassifier('rf')
    lr_classifier = TLSComplianceClassifier('lr')
    
    # Train classifiers
    rf_classifier.fit(X_train)
    lr_classifier.fit(X_train)
    
    # Get true labels for test set
    y_test = rf_classifier.create_compliance_labels(test_processed)
    
    # Make predictions
    rf_pred = rf_classifier.predict(X_test)
    lr_pred = lr_classifier.predict(X_test)
    
    rf_prob = rf_classifier.predict_proba(X_test)[:, 1]
    lr_prob = lr_classifier.predict_proba(X_test)[:, 1]
    
    # Calculate metrics
    results = {
        'Random Forest': {
            'Predictions': rf_pred,
            'Probabilities': rf_prob,
            'Accuracy': accuracy_score(y_test, rf_pred),
            'Feature Importance': rf_classifier.get_feature_importance()
        },
        'Logistic Regression': {
            'Predictions': lr_pred,
            'Probabilities': lr_prob,
            'Accuracy': accuracy_score(y_test, lr_pred),
            'Feature Importance': lr_classifier.get_feature_importance()
        }
    }
    
    # Print results
    print("\n=== Model Comparison ===")
    for model_name, metrics in results.items():
        print(f"\n{model_name}:")
        print(f"Accuracy: {metrics['Accuracy']:.4f}")
        
        compliant_count = sum(y_test)
        non_compliant_count = len(y_test) - compliant_count
        print(f"Compliant packets: {compliant_count}")
        print(f"Non-compliant packets: {non_compliant_count}")
    
    
    
    return results


if __name__ == "__main__":
   
    training_data = "updated_traffic.csv"
    testing_data = "test2.csv"
    
    results = compare_models(training_data, testing_data)