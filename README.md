
# SnapStream

**AWS-powered Media Upload and Analysis Platform**

SnapStream is a cloud-enabled media management platform that allows users to upload, store, and intelligently analyze audio, video, and image files. Leveraging AI and ML services, the platform automatically extracts metadata, generates transcripts, performs object and text recognition, and enables smart search functionality across media content.

---

## Key Features

### **For Users**

* Upload and manage media files: audio, video, and images.
* View and stream media uploaded by others.
* Automatically generated AI metadata for smart search:

  * **Audio:** Speech-to-text transcription, entity extraction, sentiment analysis.
  * **Images:** Object detection, text extraction (OCR).
  * **Videos:** Object detection, text extraction, thumbnail generation.
* Track personal media statistics (number of files uploaded, storage usage).

### **For Admins**

* Manage users: activate or suspend users.
* Monitor analytics:

  * Total storage used.
  * Media type distribution (images, audio, video).
  * Media processing status (completed, processing, failed).
* View recent activity and notifications (e.g., new uploads, media deletions).
* Delete media as needed to maintain platform hygiene.

---

## AI & ML Integrations

SnapStream integrates multiple AI/ML services to automate media intelligence:

* **YOLO:** Object detection in images and videos.
* **OCR:** Text extraction from images and video frames.
* **Whisper:** Speech-to-text and translation for audio.
* **OpenCV:** Video processing and thumbnail generation.

These services enable **smart search**, allowing users to query media by content, text, entities, or sentiment.

---

## Tech Stack

* **Backend:** Flask, Python
* **Database:** DynamoDB (storing users, media, admins, activities)
* **Notifications:** AWS SNS
* **File Storage:** local storage 
* **AI/ML:** YOLO, Whisper, OCR, OpenCV
* **Task Processing:** Celery / background task queue

---

## Usage Overview

1. **User Workflow:**

   * Sign up / log in.
   * Upload media files.
   * Access AI-generated metadata and use smart search.
   * Stream or download media.

2. **Admin Workflow:**

   * Log in using admin credentials.
   * Manage user accounts.
   * View analytics and media statistics.
   * Delete media or monitor system activity.
