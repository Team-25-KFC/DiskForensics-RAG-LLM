input<<<<<<< HEAD
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts import base
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, root_mean_squared_error
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor


mcp = FastMCP("DataAnalysis")


@mcp.tool()
def describe_column(csv_path: str, column: str) -> dict:
    """
    Get summary statistics (count, mean, std, min, max, etc.) for a specific column in a CSV file.

    Args:
        csv_path (str): The file path to the CSV file.
        column (str): The name of the column to compute statistics for.

    Returns:
        dict: A dictionary containing summary statistics of the specified column.
    """
    df = pd.read_csv(csv_path)
    if column not in df.columns:
        raise ValueError(f"Column '{column}' not found in CSV.")
    return df[column].describe().to_dict()


@mcp.tool()
def plot_histogram(csv_path: str, column: str, bins: int = 10) -> str:
    """
    Generate and save a density histogram for a specific column in a CSV file.

    Args:
        csv_path (str): The file path to the CSV file.
        column (str): The name of the column to visualize.
        bins (int, optional): Number of histogram bins. Defaults to 10.

    Returns:
        str: The file path to the saved density histogram image.
    """
    df = pd.read_csv(csv_path)
    if column not in df.columns:
        raise ValueError(f"Column '{column}' not found in CSV.")

    plt.figure(figsize=(8, 6))
    sns.histplot(
        df[column].dropna(),
        bins=bins,
        kde=True,
        stat="density",
        edgecolor="black",
        alpha=0.6,
    )
    plt.xlabel(column)
    plt.ylabel("Density")
    plt.title(f"Density Histogram of {column}")

    output_path = f"{column}_density_hist.png"
    plt.savefig(output_path)
    plt.close()

    return output_path


@mcp.tool()
def model(csv_path: str, x_columns: list, y_column: str) -> dict:
    """
    Automatically train a model (classification or regression) based on the target column type.

    Args:
        csv_path: Path to CSV file.
        x_columns: List of feature column names.
        y_column: Target column name.

    Returns:
        Dictionary with model type, performance metric, and score.
    """
    df = pd.read_csv(csv_path)

    for col in x_columns + [y_column]:
        if col not in df.columns:
            raise ValueError(f"Column '{col}' not found in CSV.")

    X = df[x_columns]
    y = df[y_column]

    for col in X.select_dtypes(include=["object"]).columns:
        X[col] = LabelEncoder().fit_transform(X[col])

    is_classification = y.dtype == "object" or len(y.unique()) <= 10

    if is_classification:
        y = LabelEncoder().fit_transform(y)
        model = RandomForestClassifier()
        metric_name = "accuracy"
    else:
        model = RandomForestRegressor()
        metric_name = "rmse"

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    if is_classification:
        score = accuracy_score(y_test, y_pred)
        model_type = "classification"
    else:
        score = root_mean_squared_error(y_test, y_pred, squared=False)
        model_type = "regression"

    return {"model_type": model_type, "metric": metric_name, "score": score}


@mcp.prompt()
def default_prompt(message: str) -> list[base.Message]:
    return [
        base.AssistantMessage(
            "You are a helpful data analysis assistant. \n"
            "Please clearly organize and return the results of the tool calling and the data analysis."
        ),
        base.UserMessage(message),
    ]


if __name__ == "__main__":
    mcp.run(transport="stdio")
=======
import requests
import numpy as np
import json
from langflow.custom.custom_component.component import Component
from langflow.io import MessageTextInput, Output
from langflow.schema.data import Data


class Reranker(Component):
    display_name = "Reranker"
    description = "Rerank documents using LM Studio embeddings (api/v0)."
    icon = "sort"
    name = "Reranker"

    inputs = [
        MessageTextInput(
            name="docs",
            display_name="Documents",
            info="List of docs (string list or list of JSON objects with 'text').",
            value="[]",
            tool_mode=True,
        ),
        MessageTextInput(
            name="query",
            display_name="Query",
            info="Search query text",
            value="칼바람",
            tool_mode=True,
        ),
    ]

    outputs = [
        Output(display_name="Output", name="output", method="rerank"),
    ]

    def get_embedding(self, text: str, model: str = "text-embedding-bge-reranker-v2-m3"):
        url = "http://127.0.0.1:1234/api/v0/embeddings"
        payload = {"model": model, "input": [text]}
        response = requests.post(url, json=payload)
        response.raise_for_status()
        result = response.json()
        return np.array(result["data"][0]["embedding"], dtype=np.float32)

    def cosine_similarity(self, a, b):
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

    def rerank(self) -> Data:
        import json

        # 입력 docs 처리
        docs = self.docs
        if isinstance(docs, str):
            try:
                docs = json.loads(docs)
            except Exception:
                docs = [docs]

        query_text = self.query if hasattr(self, "query") else "query"
        query_emb = self.get_embedding(query_text)

        reranked_docs = []
        for doc in docs:
            if isinstance(doc, dict):
                text = doc.get("text", "")
                doc_id = doc.get("id")
            else:
                text = str(doc)
                doc_id = None

            if not text.strip():
                continue

            doc_emb = self.get_embedding(text)
            score = self.cosine_similarity(query_emb, doc_emb)

            reranked_docs.append({
                "id": doc_id,
                "text": text,
                "score": score
            })

        reranked_docs.sort(key=lambda x: x["score"], reverse=True)
        top_n = reranked_docs[:5]

        return Data(value=top_n)
>>>>>>> 1194661 (ccit2)
