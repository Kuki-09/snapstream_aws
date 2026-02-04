import logging
import os
from celery_worker import celery
import math
import spacy
from textblob import TextBlob
import cv2
import pytesseract
from collections import Counter
from datetime import datetime
import boto3

logging.basicConfig(level=logging.INFO)

dynamodb = boto3.resource("dynamodb", region_name="us-east-1")

media_table = dynamodb.Table("media")
activity_table = dynamodb.Table("activity")

nlp = spacy.load("en_core_web_sm")


def log_activity(user_id, activity_type, description):
    activity_item = {
        "user_id": user_id,
        "timestamp": datetime.utcnow().isoformat(),
        "type": activity_type,
        "description": description,
        "read": False
    }
    activity_table.put_item(Item=activity_item)


def get_media_item(media_id):
    resp = media_table.get_item(Key={"media_id": media_id})
    return resp.get("Item")


def update_media_item(media_id, update_data):
    update_expr = "SET " + ", ".join(f"#{k}=:{k}" for k in update_data.keys())
    expr_names = {f"#{k}": k for k in update_data.keys()}
    expr_values = {f":{k}": v for k, v in update_data.items()}

    media_table.update_item(
        Key={"media_id": media_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values
    )


@celery.task(bind=True)
def process_media_task(self, media_id):

    media = get_media_item(media_id)
    if not media:
        logging.error(f"Media {media_id} not found!")
        return

    file_path = os.path.join("uploads", media["file_path"])

    if not os.path.exists(file_path):
        update_media_item(media_id, {"status": "Failed", "progress": 0})
        return

    update_media_item(media_id, {"status": "Processing", "progress": 0})

    # ---------------- AUDIO ----------------
    if media["type"] == "audio":

        # DEMO MODE → Skip Whisper
        update_media_item(media_id, {
            "ai_metadata": {"note": "Audio AI disabled in demo"},
            "progress": 100,
            "status": "Completed"
        })

        return

    # ---------------- IMAGE ----------------
    elif media["type"] == "image":

        img = cv2.imread(file_path)

        try:
            text = pytesseract.image_to_string(img)
        except:
            text = ""

        ai_metadata = {
            "objects": ["Object detection disabled in demo"],
            "text": text.strip()
        }

        update_media_item(media_id, {
            "ai_metadata": ai_metadata,
            "progress": 100,
            "status": "Completed"
        })

        return

    # ---------------- VIDEO ----------------
    elif media["type"] == "video":

        cap = cv2.VideoCapture(file_path)

        fps = cap.get(cv2.CAP_PROP_FPS) or 1
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 1
        duration = total_frames / fps

        update_media_item(media_id, {
            "duration": duration,
            "ai_metadata": {"note": "Video AI disabled in demo"},
            "progress": 100,
            "status": "Completed"
        })

        cap.release()
