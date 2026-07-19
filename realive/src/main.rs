use qdrant_client::{
    qdrant::QueryPointsBuilder,
    Qdrant
};

use ollama_rs::{
    generation::{
        completion::request::GenerationRequest,
        embeddings::request::GenerateEmbeddingsRequest    
    },
    Ollama
};

use serde_json::json;

use std::fs;
use text_splitter::TextSplitter;
use std::error::Error;
use uuid::Uuid;

const QDRANT_URL: &str = "http://dev05:6334";
//const BOOK_URL: &str = "C:\\users\\W530\\Downloads\\dmbok.md";
const BOOK_URL: &str = "C:\\users\\W530\\Downloads\\rando_readme.md";
const MODEL_NAME: &str = "nomic-embed-text";

struct DocumentChunk {
    pub file_name: String,
    pub chunk: String
}

struct DocPoint {
    pub point_id: String,
    pub file_name: String,
    pub vector: Vec<f32>
}

struct PointMetadata {
    pub filename: String,
    pub timestamp: String
}



async fn get_embedding(text_chunk: &str) -> Result<Vec<f32>, Box<dyn Error>> {
    let ollama_client = Ollama::default();

    let embedding_request = GenerateEmbeddingsRequest::new(
        MODEL_NAME.to_string(),
        text_chunk.into()
    );

    let response = ollama_client.generate_embeddings(embedding_request).await?;

    let resp_vector = response.embeddings.into_iter().next().ok_or("[!] empty list")?;

    Ok(resp_vector)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("[*] starting...");

    let qdrant = Qdrant::from_url(QDRANT_URL).build()?;
    
    let file_content = fs::read_to_string(&BOOK_URL)?;  
    
    let mut all_chunks: Vec<DocumentChunk> = Vec::new();
    
    let splitter = TextSplitter::new(512);

    for chunk in splitter.chunks(file_content.as_str()) {
        all_chunks.push(DocumentChunk {
            file_name: BOOK_URL.to_string(),
            chunk: chunk.to_string(),
        });
    }

    println!("    [*] chunks: {}", all_chunks.len());

    println!("    [*] processing chunks...");

    let mut points = Vec::new();

    for chunk in all_chunks {
        // get embedding I spose 
        let embedding_vector: Vec<f32> = get_embedding(chunk.chunk.as_str()).await?;

        let point_id = Uuid::new_v4().to_string();

        let payload = 

        let point = DocPoint{
            point_id: point_id,
            file_name: BOOK_URL.to_string(),
            vector: embedding_vector.clone()
        };

        points.push(point);

    }


    
    println!("[.] Done!");

    Ok(())
}
