"""
spark_orchestrator.py — PySpark implementation of the concurrent multi-agent demo.

Instead of spawning macOS terminal windows, this script distributes
specialist tasks to PySpark executors, which query LLM inference engines
running on the DGX nodes.
"""

import argparse
import pandas as pd
from pyspark.sql import SparkSession
from pyspark.sql.types import StructType, StructField, StringType
from typing import Iterator

# Assuming demo modules are available in Python Path or deployed via Spark
# from demo.scenarios import get_scenario
# from demo.utils import stream_llm

def process_agent_partition(iterator: Iterator[pd.DataFrame]) -> Iterator[pd.DataFrame]:
    """
    Spark mapInPandas function. 
    Runs on the DGX Spark Executors.
    """
    import requests # Standard REST calls to node-local LLM

    # In a real DGX setup, each node might run its own vLLM instance bound to the local GPUs.
    # We query the local inference server.
    LOCAL_LLM_URL = "http://localhost:8000/v1/chat/completions"
    
    for pdf in iterator:
        results = []
        for _, row in pdf.iterrows():
            system_prompt = row['system_prompt']
            instruction = row['instruction']
            
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": instruction})
            
            try:
                response = requests.post(LOCAL_LLM_URL, json={
                    "model": "gemma-4",
                    "messages": messages,
                    "max_tokens": 1024
                })
                # Fallback extraction
                result_text = response.json()['choices'][0]['message']['content']
            except Exception as e:
                result_text = f"Error: {e}"
                
            results.append(result_text)
            
        pdf['result'] = results
        yield pdf

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", default="translate")
    parser.add_argument("--topic", default="Gemma 4 distributed on DGX Spark")
    args = parser.parse_args()

    spark = SparkSession.builder.appName("Gemma4-Concurrent-Spark").getOrCreate()

    # In a real execution, we would call plan_tasks(api_url, scenario, topic)
    # For this example, we mock the planned tasks
    planned_tasks = [
        {"name": f"Agent_{i}", "instruction": f"Process {args.topic} segment {i}", "system_prompt": "You are a specialist."}
        for i in range(16) # 16 Concurrent agents
    ]

    print(f"Distributed Orchestrator: Planning complete. {len(planned_tasks)} tasks generated.")
    
    # ─── Dispatch via Spark ───────────────────────────────────────
    df = spark.createDataFrame(planned_tasks)
    
    # Define output schema
    schema = StructType([
        StructField("name", StringType(), True),
        StructField("instruction", StringType(), True),
        StructField("system_prompt", StringType(), True),
        StructField("result", StringType(), True)
    ])
    
    # Run concurrent inference across DGX cluster
    result_df = df.mapInPandas(process_agent_partition, schema=schema)
    
    # ─── Collect and Assemble ──────────────────────────────────────
    results_list = result_df.collect()
    
    results = {row['name']: row['result'] for row in results_list}
    print("All distributed tasks completed!")
    
    for name, res in results.items():
        print(f"{name}: {res[:50]}...")
        
    spark.stop()

if __name__ == "__main__":
    main()
