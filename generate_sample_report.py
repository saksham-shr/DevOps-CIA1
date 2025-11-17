"""
Generate a sample report for testing/demo purposes
"""
import os
import sys
from report_logic import generate_report_pdf
from datetime import datetime

# Sample data for report generation
sample_data = {
    "general_info": {
        "Activity Type": "Workshop",
        "Sub Category": "Technical Workshop",
        "Title of the Activity": "Introduction to Machine Learning",
        "Start Date": "2024-11-15",
        "End Date": "2024-11-15",
        "Start Time": "10:00",
        "End Time": "16:00",
        "Venue": "Main Auditorium, Christ University",
        "Collaboration/Sponsor": "Department of AI, ML & Data Science"
    },
    "speakers": [
        {
            "name": "Dr. John Smith",
            "title": "Professor",
            "organization": "MIT",
            "contact": "john.smith@mit.edu",
            "presentation_title": "Machine Learning Fundamentals"
        },
        {
            "name": "Dr. Jane Doe",
            "title": "Senior Researcher",
            "organization": "Stanford University",
            "contact": "jane.doe@stanford.edu",
            "presentation_title": "Deep Learning Applications"
        }
    ],
    "participants": [
        {
            "type": "Faculty",
            "count": "15"
        },
        {
            "type": "Student",
            "count": "85"
        },
        {
            "type": "Research Scholar",
            "count": "10"
        }
    ],
    "synopsis": {
        "highlights": "Comprehensive introduction to ML concepts\nHands-on coding sessions\nReal-world case studies\nIndustry expert insights",
        "highlights_format": "bullet",
        "key_takeaways": "Understanding of basic ML algorithms\nPractical implementation skills\nKnowledge of ML applications\nNetworking opportunities",
        "key_takeaways_format": "numbered",
        "summary": "The workshop provided a comprehensive introduction to machine learning, covering fundamental concepts, practical implementations, and real-world applications. Participants engaged in hands-on coding sessions and learned from industry experts.",
        "summary_format": "plain",
        "follow_up": "Organize advanced ML workshop\nCreate study groups\nShare resources on online platform\nFollow-up session in 2 months",
        "follow_up_format": "bullet"
    },
    "preparers": [
        {
            "name": "Dr. Saksham Sharma",
            "designation": "Assistant Professor",
            "signature_path": None  # No signature for demo
        }
    ],
    "speaker_profile": {
        "bio": "Dr. John Smith is a renowned expert in machine learning with over 20 years of experience. He has published numerous papers in top-tier conferences and journals.",
        "image_path": None  # No image for demo
    },
    "photos": [],  # No photos for demo
    "attendance_list": [],
    "brochure": [],
    "notice": [],
    "feedback": [],
    "impact": []
}

def main():
    print("Generating sample report...")
    
    try:
        # Generate PDF
        pdf_bytes, filename = generate_report_pdf(sample_data)
        
        # Save to file
        output_path = os.path.join("sample_report.pdf")
        with open(output_path, 'wb') as f:
            f.write(pdf_bytes)
        
        print(f"Sample report generated successfully!")
        print(f"Saved as: {output_path}")
        print(f"File size: {len(pdf_bytes)} bytes")
        return True
        
    except Exception as e:
        print(f"Error generating report: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

