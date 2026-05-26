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

use std::fs;

use text_splitter::TextSplitter;


use std::error::Error;

const QDRANT_URL: &str = "http://dev05:6334";
const BOOK_URL: &str = "C:\\users\\W530\\Downloads\\dmbok.md";

struct DocumentChunk {
    pub file_name: String,
    pub chunk: String
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("[*] starting...");

    let qdrant = Qdrant::from_url(QDRANT_URL).build()?;

    let file_content = match fs::read_to_string(&BOOK_URL) {
        Ok(txt) => txt,
        Err(e) => {
            return Err(Box::new(e))
        }
    };

    let mut all_chunks: Vec<DocumentChunk> = Vec::new();
    
    let splitter = TextSplitter::new(512);

    for chunk in splitter.chunks(file_content.as_str()) {
        all_chunks.push(DocumentChunk {
            file_name: BOOK_URL.to_string(),
            chunk: chunk.to_string(),
        });
    }

    println!("    [*] chunks: {}", all_chunks.len());
    
    println!("[.] Done!");

    Ok(())
}
