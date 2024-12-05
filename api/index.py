from urllib.parse import urljoin, urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import datetime
from api.registry import EncryptionRegistry
from api.utils import generate_id
import base64
import requests
import os
import json
import logging

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Set 16MB max file size for uploads
CORS(app, resources={r"/api/*": {"origins": "*"}}, methods=["GET", "POST", "DELETE"])

# Load Redis configurations
UPSTASH_REDIS_URL = os.getenv("UPSTASH_REDIS_URL")
UPSTASH_REDIS_PASSWORD = os.getenv("UPSTASH_REDIS_PASSWORD")
HEADERS = {"Authorization": f"Bearer {UPSTASH_REDIS_PASSWORD}"}

# Helper functions
def safe_request(method, endpoint_path, headers=None, data=None):
    base_url = UPSTASH_REDIS_URL
    full_url = base_url + endpoint_path
    if method == "get":
        return requests.get(full_url, headers=headers)
    elif method == "post":
        return requests.post(full_url, headers=headers, json=data)
    raise ValueError(f"Unsupported HTTP method: {method}")

def is_valid_base64(s: str) -> bool:
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def add_padding(base64_string):
    return base64_string + "=" * (-len(base64_string) % 4)

# Health check route
@app.route("/")
def health_check():
    return {"status": "running"}, 200

# Encode API
@app.route("/api/encode", methods=["POST"])
def encode():
    """
    Handles file encryption and stores the result in Redis.
    """
    try:
        # Parse request data
        data = request.json
        logging.debug(f"Request received for encoding: {data}")
        
        # Extract encryption details
        algorithm_name = data.get("algorithm", "AES256")
        password = data.get("password")
        file_data = base64.b64decode(data.get("file_data"))

        # Validate algorithm
        algorithm = EncryptionRegistry.get(algorithm_name)
        if algorithm is None:
            raise ValueError(f"Algorithm {algorithm_name} not found in registry.")

        # Encrypt file data
        encrypted_data, metadata = algorithm.encrypt(file_data, password)

        # Add metadata for Redis
        metadata["encrypted_data"] = base64.b64encode(encrypted_data).decode()
        metadata["reads"] = int(data.get("reads", 1))
        metadata["ttl"] = int(data.get("ttl", 86400))
        metadata["file_name"] = data.get("file_name", "unknown")
        metadata["file_type"] = data.get("file_type", "application/octet-stream")

        # Ensure all metadata values are JSON serializable
        for key, value in metadata.items():
            if isinstance(value, bytes):
                metadata[key] = base64.b64encode(value).decode()

        # Generate unique file ID and prepare Redis commands
        file_id = generate_id()
        key = f"cipher_share:{file_id}"
        redis_pipeline = [[f"hset", key, k, v] for k, v in metadata.items()]
        redis_pipeline.append(["expire", key, metadata["ttl"]])

        # Store encrypted data in Redis
        response = requests.post(f"{UPSTASH_REDIS_URL}/pipeline", headers=HEADERS, json=redis_pipeline)
        logging.debug(f"Redis response: {response.text}")

        # Handle Redis errors
        if response.status_code != 200:
            return jsonify({"error": "Failed to store encrypted data"}), 500

        # Generate and return shareable link
        domain = os.getenv("DOMAIN", "https://ciphare.vercel.app")
        return jsonify({"file_id": file_id, "share_link": f"{domain}/decode/{file_id}"})
    except Exception as e:
        logging.error(f"Error during encoding: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Decode API
# Helper functions
def is_valid_base64(s: str) -> bool:
    """Check if a string is valid Base64."""
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False

def add_padding(base64_string):
    """Ensure Base64 string has proper padding."""
    return base64_string + "=" * (-len(base64_string) % 4)

# Decode API
@app.route("/api/decode", methods=["POST"])
def decode():
    """
    Handles file decryption and retrieves the result from Redis.
    """
    try:
        # Parse request data
        data = request.json
        logging.debug(f"Request received for decoding: {data}")

        # Extract decryption details
        file_id = data.get("file_id")
        password = data.get("password")
        algorithm_name = data.get("algorithm", "AES256")

        # Validate inputs
        if not file_id or not password:
            return jsonify({"error": "File ID and password are required"}), 400

        # Fetch metadata from Redis
        key = f"cipher_share:{file_id}"
        response = requests.get(f"{UPSTASH_REDIS_URL}/hgetall/{key}", headers=HEADERS)
        logging.debug(f"Redis response for key {key}: {response.text}")

        if response.status_code != 200 or not response.json().get("result"):
            return jsonify({"error": "File not found or expired"}), 404

        raw_result = response.json()["result"]
        metadata = {}

        # Process metadata
        for i in range(0, len(raw_result), 2):
            k, v = raw_result[i], raw_result[i + 1]
            if k in ["file_name", "file_type"]:
                metadata[k] = v  # Skip decoding for plain strings
            elif k in ["ttl", "reads"]:
                metadata[k] = int(v)  # Parse as integers
            else:
                if not is_valid_base64(v):
                    logging.error(f"Invalid Base64 string for key {k}: {v}")
                    return jsonify({"error": f"Invalid Base64 string for key {k}"}), 400
                metadata[k] = base64.b64decode(add_padding(v))

        encrypted_data = metadata.pop("encrypted_data")

        # Validate algorithm
        algorithm = EncryptionRegistry.get(algorithm_name)
        if not algorithm:
            return jsonify({"error": f"Algorithm {algorithm_name} not supported"}), 400

        # Decrypt file data
        decrypted_data = algorithm.decrypt(encrypted_data, password, metadata)

        # Update `reads` or delete if exhausted
        remaining_reads = metadata["reads"] - 1
        if remaining_reads > 0:
            requests.post(
                f"{UPSTASH_REDIS_URL}/hincrby/{key}/reads/-1",
                headers=HEADERS
            )
        else:
            requests.post(
                f"{UPSTASH_REDIS_URL}/del/{key}",
                headers=HEADERS
            )

        # Return decrypted file data and metadata
        return jsonify({
            "decrypted_data": base64.b64encode(decrypted_data).decode(),
            "file_name": metadata.get("file_name", "unknown"),
            "file_type": metadata.get("file_type", "application/octet-stream"),
            "remaining_reads": remaining_reads
        })
    except Exception as e:
        logging.error(f"Error during decoding: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Posts Routes (similar to original)
# Safe request helper function to avoid SSRF vulnerabilities
# Helper function for safe Redis requests
def safe_request(method, endpoint_path, headers=None, data=None):
    base_url = UPSTASH_REDIS_URL
    full_url = urljoin(base_url, endpoint_path)
    parsed_url = urlparse(full_url)

    # Allowed paths to avoid SSRF vulnerabilities
    allowed_paths = ["/hset/", "/hget/", "/hincrby/", "/del/", "/smembers/", "/expire/", "/keys/", "/hgetall/", "/pipeline"]
    if not any(parsed_url.path.startswith(path) for path in allowed_paths):
        raise ValueError(f"Security Exception: Unsafe URL path detected: {parsed_url.path}")

    # Serialize data if provided
    if data is not None:
        data = json.dumps(data)

    # Make the request
    if method == "get":
        return requests.get(full_url, headers=HEADERS)
    elif method == "post":
        return requests.post(full_url, headers=HEADERS, data=data)
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")

@app.route("/api/posts", methods=["GET", "POST"])
def api_posts():
    if request.method == "POST":
        # Logic for creating a new post
        data = request.json
        title = data.get("title", "").strip()
        content = data.get("content", "").strip()
        author = data.get("author", "Anonymous").strip()
        ttl = int(data.get("ttl", 90 * 24 * 60 * 60))  # Default to 3 months in seconds

        post_id = generate_id()
        key = f"post:{post_id}"
        post_data = {
            "title": title,
            "content": content,
            "author": author,
            "likes": 0,
            "created_at": datetime.utcnow().isoformat(),
            "comments": []
        }

        redis_pipeline = [
            ["hset", key, "title", title],
            ["hset", key, "content", content],
            ["hset", key, "author", author],
            ["hset", key, "likes", 0],
            ["hset", key, "created_at", post_data["created_at"]],
            ["hset", key, "comments", json.dumps([])],
            ["expire", key, ttl]
        ]

        response = safe_request("post", "/pipeline", headers=HEADERS, data=redis_pipeline)
        if response.status_code == 200:
            return jsonify({"message": "Post created successfully", "post_id": post_id}), 201
        return jsonify({"error": "Failed to create post"}), 500

    elif request.method == "GET":
        # Logic for retrieving all posts
        response = safe_request("get", "/keys/post:*", headers=HEADERS)
        if response.status_code != 200:
            return jsonify({"error": "Failed to retrieve posts"}), 500

        keys = response.json().get("result", [])
        posts = []

        for key in keys:
            post_response = safe_request("get", f"/hgetall/{key}", headers=HEADERS)
            if post_response.status_code == 200:
                raw_post_data = post_response.json().get("result", [])
                post_data = dict(zip(raw_post_data[::2], raw_post_data[1::2]))
                post_data["_id"] = key.split(":")[1]
                post_data["likes"] = int(post_data.get("likes", 0))
                post_data["comments"] = json.loads(post_data.get("comments", "[]"))
                posts.append(post_data)

        return jsonify(sorted(posts, key=lambda x: x["likes"], reverse=True)), 200


# Route to like a post
@app.route("/api/posts/<post_id>/like", methods=["POST"])
def like_post(post_id):
    """
    Increment the 'likes' field for a post in Redis.
    """
    key = f"post:{post_id}"
    try:
        response = safe_request("post", f"/hincrby/{key}/likes/1", headers=HEADERS)
        if response.status_code == 200:
            return jsonify({"message": "Post liked successfully"}), 200
        return jsonify({"error": "Failed to like post"}), 500
    except Exception as e:
        logging.error(f"Error liking post {post_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Route to add a comment to a post
@app.route("/<post_id>/comment", methods=["POST"])
def add_comment(post_id):
    try:
        data = request.json
        content = data.get("content", "").strip()
        author = data.get("author", "Anonymous").strip()
        ttl = data.get("ttl", 90 * 24 * 60 * 60)  # Default to 90 days in seconds

        if not content or not author:
            return jsonify({"error": "Author and content are required"}), 400

        key = f"post:{post_id}"
        response = safe_request("get", f"/hget/{key}/comments", headers=HEADERS)

        if response.status_code != 200:
            return jsonify({"error": "Failed to retrieve comments"}), 500

        # Ensure comments are parsed as a list
        existing_comments = response.json().get("result", "[]")
        try:
            comments = json.loads(existing_comments)
            if not isinstance(comments, list):
                raise ValueError("Comments is not a list")
        except Exception:
            comments = []  # Reset to an empty list if parsing fails

        # Generate a unique ID for the comment's author
        author_id = generate_id()

        # Add the new comment
        new_comment = {
            "content": content,
            "author": author,
            "author_id": author_id,
            "timestamp": datetime.utcnow().isoformat(),
            "ttl": ttl,
        }
        comments.append(new_comment)

        # Update comments in Redis
        response = safe_request(
            "post", f"/hset/{key}/comments", headers=HEADERS, data={"comments": json.dumps(comments)}
        )

        if response.status_code != 200:
            return jsonify({"error": "Failed to add comment"}), 500

        # Fetch the updated post data
        post_response = safe_request("get", f"/hgetall/{key}", headers=HEADERS)
        if post_response.status_code != 200:
            return jsonify({"error": "Failed to retrieve updated post"}), 500

        raw_post_data = post_response.json().get("result", [])
        post_data = dict(zip(raw_post_data[::2], raw_post_data[1::2]))
        post_data["_id"] = key.split(":")[1]
        post_data["likes"] = int(post_data.get("likes", 0))
        post_data["comments"] = json.loads(post_data.get("comments", "[]"))
        post_data["created_at"] = post_data.get("created_at", "")

        return jsonify(post_data), 200  # Return the updated post

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Route to delete a post
@app.route("/api/posts/<post_id>", methods=["DELETE"])
def delete_post(post_id):
    """
    Delete a post from Redis.
    """
    key = f"post:{post_id}"
    try:
        response = safe_request("post", f"/del/{key}", headers=HEADERS)
        if response.status_code == 200:
            return jsonify({"message": "Post deleted successfully"}), 200
        return jsonify({"error": "Failed to delete post"}), 500
    except Exception as e:
        logging.error(f"Error deleting post {post_id}: {str(e)}")
        return jsonify({"error": str(e)}), 500
    
# Route to delete a comment from a post
@app.route("/<post_id>/comment/<int:comment_index>", methods=["DELETE"])
def delete_comment(post_id, comment_index):
    try:
        key = f"post:{post_id}"  # Define the key for Redis

        # Retrieve the existing comments
        response = safe_request("get", f"/hget/{key}/comments", headers=HEADERS)  # Get the comments from Redis hash field

        if response.status_code != 200:
            print(f"Failed to retrieve comments. Redis Error: {response.status_code}, {response.text}")
            return jsonify({"error": "Failed to retrieve comments"}), 500

        # Parse comments and remove the specified comment
        comments = json.loads(response.json().get("result", "[]"))
        if 0 <= comment_index < len(comments):
            deleted_comment = comments.pop(comment_index)
            print(f"Deleted comment: {deleted_comment}")

            # Update the comments in Redis
            response = safe_request(
                "post",
                f"/hset/{key}/comments",
                headers=HEADERS,
                data={"comments": json.dumps(comments)}
            )

            if response.status_code == 200:
                return jsonify({"message": "Comment deleted successfully"}), 200
            else:
                print(f"Failed to delete comment. Redis Error: {response.status_code}, {response.text}")
                return jsonify({"error": "Failed to delete comment"}), 500
        else:
            return jsonify({"error": "Comment index out of range"}), 404

    except Exception as e:
        print(f"Error in deleting comment: {e}")
        return jsonify({"error": "An error occurred while deleting the comment"}), 500

# Vercel requires this for deployment
handler = app

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
