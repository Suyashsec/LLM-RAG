import chromadb
import os
import glob

# 1. Initialize Chroma DB
# We delete the old DB reference to start fresh
if os.path.exists("./chroma_db"):
    print("Updating existing database...")
else:
    print("Creating new database...")

client = chromadb.PersistentClient(path="./chroma_db")

# Delete old collection if it exists to avoid duplicate data
try:
    client.delete_collection("alloy_docs")
except:
    pass

collection = client.create_collection(name="alloy_docs")

# 2. Read all files from the 'docs' folder
doc_files = glob.glob("docs/*")
documents = []
ids = []
id_counter = 0

print(f"Found {len(doc_files)} documentation files.")

for file_path in doc_files:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()

        # Simple strategy: Split by double newlines (paragraphs)
        chunks = text.split("\n\n")

        for chunk in chunks:
            if len(chunk.strip()) > 50: # Ignore tiny empty lines
                documents.append(chunk)
                ids.append(f"doc_{id_counter}")
                id_counter += 1
    except Exception as e:
        print(f"Skipping {file_path}: {e}")

# 4. Add to Database
if documents:
    print(f"Ingesting {len(documents)} text chunks into Chroma DB...")

    # Add in batches to avoid memory issues
    batch_size = 100
    for i in range(0, len(documents), batch_size):
        end = min(i + batch_size, len(documents))
        collection.add(
            documents=documents[i:end],
            ids=ids[i:end]
        )
    print("✅ Knowledge Base Successfully Updated!")
else:
    print("⚠️ No valid text found in docs folder.")