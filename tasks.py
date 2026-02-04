import logging
import os
from celery_worker import celery
import math
import whisper 
import spacy
from textblob import TextBlob
import cv2
import pytesseract
from ultralytics import YOLO  
from collections import Counter
from datetime import datetime
import boto3
from boto3.dynamodb.conditions import Attr

logging.basicConfig(level=logging.INFO)


dynamodb = boto3.resource("dynamodb", region_name="us-east-1")  


media_table = dynamodb.Table("media")
activity_table = dynamodb.Table("activity")


nlp = spacy.load("en_core_web_sm")
whisper_model = whisper.load_model("base")  
yolo_model = YOLO("yolov8n.pt")  


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
    """Update fields in the media DynamoDB table"""
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
        logging.error(f"File {file_path} does not exist!")
        update_media_item(media_id, {"status": "Failed", "progress": 0})
        return

    update_media_item(media_id, {"status": "Processing", "progress": 0})
    log_activity(media["user_id"], "media_processing", f"Started processing {media['title']}")

    # ---------------- AUDIO ----------------
    if media["type"] == "audio":
        try: 
            logging.info(f"🚀 Audio processing for {media_id}")

            result = whisper_model.transcribe(file_path)
            transcript = result["text"]

            doc = nlp(transcript)
            entities = [ent.text for ent in doc.ents]

            polarity = TextBlob(transcript).sentiment.polarity
            sentiment = (
                "Positive" if polarity > 0.1 else
                "Negative" if polarity < -0.1 else
                "Neutral"
            )

            ai_metadata = {
                "transcript": transcript,
                "entities": entities,
                "sentiment": sentiment
            }

            update_media_item(media_id, {"ai_metadata": ai_metadata, "progress": 100, "status": "Completed"})
            log_activity(media["user_id"], "media_processed", f"Audio processing completed for {media['title']}")
        except Exception as e:
            logging.error(f"Audio processing failed for {media_id}: {e}")
            update_media_item(media_id, {"status": "Failed", "progress": 0})
        return

    # ---------------- IMAGE ----------------
    elif media["type"] == "image":
        logging.info(f"🖼 Image processing for {media_id}")
        try:
            results = yolo_model(file_path)
            objects = []
            for r in results:
                for obj in r.boxes.cls:
                    objects.append(yolo_model.names[int(obj)])

            img = cv2.imread(file_path)
            try:
                text = pytesseract.image_to_string(img)
            except Exception:
                text = ""

            ai_metadata = {
                "objects": list(set(objects)),
                "text": text.strip()
            }

            update_media_item(media_id, {"ai_metadata": ai_metadata, "progress": 100, "status": "Completed"})
            log_activity(media["user_id"], "media_processed", f"Image processing completed for {media['title']}")
        except Exception as e:
            logging.error(f"Image processing failed for {media_id}: {e}")
            update_media_item(media_id, {"status": "Failed", "progress": 0})
        return

    # ---------------- VIDEO ----------------    
    elif media["type"] == "video":
        import easyocr
        logging.info(f"🎥 Video processing for {media_id}")

        reader = easyocr.Reader(['en'], gpu=False)

        cap = cv2.VideoCapture(file_path)
        fps = cap.get(cv2.CAP_PROP_FPS) or 1
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 1
        duration = total_frames / fps
        update_media_item(media_id, {"duration": duration})

        processing_failed = False
        frame_interval = max(1, int(fps * 0.5))

        objects_count = {}
        ocr_text_list = []

        thumb_dir = os.path.join("uploads", "thumbnails")
        os.makedirs(thumb_dir, exist_ok=True)

        ret, frame = cap.read()
        thumb_rel_path = None
        while ret and thumb_rel_path is None:
            if frame is not None and frame.any():
                thumb_rel_path = f"thumbnails/{media_id}.jpg"
                thumb_abs_path = os.path.join("uploads", thumb_rel_path)
                cv2.imwrite(thumb_abs_path, frame)
            ret, frame = cap.read()
        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
        frame_count = 0

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            if frame_count % frame_interval == 0:
                try:
                    results = yolo_model(frame)
                    for r in results:
                        for box, cls_id, conf in zip(r.boxes.xyxy, r.boxes.cls, r.boxes.conf):
                            conf = float(conf)
                            cls_id = int(cls_id)
                            obj_name = yolo_model.names[cls_id]
                            if conf >= 0.25: 
                                objects_count[obj_name] = objects_count.get(obj_name, 0) + 1
                except Exception as e:
                    logging.warning(f"YOLO failed on frame {frame_count}: {e}")
                    processing_failed = True

                try:
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    gray = cv2.bilateralFilter(gray, 9, 75, 75)
                    ocr_results = reader.readtext(gray)
                    for bbox, text, conf in ocr_results:
                        if conf > 0.4: 
                            cleaned_text = text.strip()
                            if len(cleaned_text) > 2: 
                                ocr_text_list.append(cleaned_text)
                except Exception as e:
                    logging.warning(f"EasyOCR failed on frame {frame_count}: {e}")
                    processing_failed = True
                update_media_item(media_id, {"progress": min(95, math.floor((frame_count / total_frames) * 100))})

            frame_count += 1

        cap.release()
        if processing_failed:
            update_media_item(media_id, {
               "status": "Failed",
               "progress": 0
            })
            log_activity(media["user_id"], "media_failed", f"Video processing failed for {media['title']}")
            return 


        objects_sorted = sorted(objects_count.items(), key=lambda x: x[1], reverse=True)
        top_objects = [obj for obj, count in objects_sorted[:10]]
        text_counter = Counter(ocr_text_list)
        top_texts = [text for text, freq in text_counter.most_common(20)]
        aggregated_text = " | ".join(top_texts)

        ai_metadata = {
            "objects": top_objects,
            "text": aggregated_text,
            "thumbnail": thumb_rel_path
        }

        update_media_item(media_id, {"thumbnail_path": thumb_rel_path,"ai_metadata": ai_metadata, "progress": 100, "status": "Completed"})
        log_activity(media["user_id"], "media_processed", f"Video processing completed for {media['title']}")

    else:
        update_media_item(media_id, {"status": "Completed", "progress": 100})
