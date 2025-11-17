import os
import logging
from io import BytesIO
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
)
from reportlab.lib import colors
from PIL import Image as PILImage
import tempfile

# Setup logger
logger = logging.getLogger('report_generator.report')

try:
    from pdf2image import convert_from_path
    PDF2IMAGE_AVAILABLE = True
    logger.info("PDF2IMAGE library available - PDF conversion enabled")
except ImportError:
    PDF2IMAGE_AVAILABLE = False
    logger.warning("pdf2image not available. PDF conversion will not work.")


# =============================
# CONFIGURATION
# =============================
MAX_IMAGE_WIDTH_INCH = 6.0
MAX_IMAGE_PX = 1200
MAX_FILE_SIZE_MB = 10
COMPRESSION_QUALITY = 75  # Lower quality for better compression

BASE_FONT = "Times-Roman"
BOLD_FONT = "Times-Bold"

styles = getSampleStyleSheet()

# =============================
# STYLES
# =============================
styles.add(ParagraphStyle(
    name='HeaderMain',
    fontName=BOLD_FONT, fontSize=16, alignment=1, spaceAfter=6
))
styles.add(ParagraphStyle(
    name='HeaderSub',
    fontName=BASE_FONT, fontSize=13, alignment=1, spaceAfter=2
))
styles.add(ParagraphStyle(
    name='SectionTitle',
    fontName=BOLD_FONT, fontSize=12.5, alignment=0, spaceBefore=14, spaceAfter=6
))
styles.add(ParagraphStyle(
    name='SubsectionTitle',
    fontName=BOLD_FONT, fontSize=11.5, alignment=0, spaceBefore=8, spaceAfter=4
))
styles.add(ParagraphStyle(
    name='NormalText',
    fontName=BASE_FONT, fontSize=11, leading=15
))
styles.add(ParagraphStyle(
    name='TableKey',
    fontName=BOLD_FONT, fontSize=11, leading=14
))
styles.add(ParagraphStyle(
    name='TableValue',
    fontName=BASE_FONT, fontSize=11, leading=14
))
styles.add(ParagraphStyle(
    name='CenteredBold',
    fontName=BOLD_FONT, fontSize=16, alignment=1, spaceBefore=6, spaceAfter=6
))
styles.add(ParagraphStyle(
    name='PhotoHeading',
    fontName=BOLD_FONT, fontSize=14, alignment=1, spaceBefore=6, spaceAfter=8
))


# =============================
# UTILITIES
# =============================

def ensure_image_resized(path):
    """Resize and compress image if too large."""
    try:
        if not path or not os.path.exists(path):
            logger.warning(f"Image path does not exist: {path}")
            return None
        
        # Check file size
        file_size_mb = os.path.getsize(path) / (1024 * 1024)
        
        img = PILImage.open(path)
        original_w, original_h = img.size
        
        # Convert RGBA to RGB if necessary (for JPEG compatibility)
        if img.mode in ('RGBA', 'LA', 'P'):
            background = PILImage.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode in ('RGBA', 'LA') else None)
            img = background
        
        w, h = img.size
        
        # Always resize if dimensions are too large (more aggressive)
        needs_resize = False
        if w > MAX_IMAGE_PX or h > MAX_IMAGE_PX:
            ratio = min(MAX_IMAGE_PX / float(w), MAX_IMAGE_PX / float(h))
            new_size = (int(w * ratio), int(h * ratio))
            img = img.resize(new_size, PILImage.LANCZOS)
            w, h = new_size
            needs_resize = True
        
        # Always compress if file size is too large or if we resized
        if file_size_mb > MAX_FILE_SIZE_MB or needs_resize or w > MAX_IMAGE_PX or h > MAX_IMAGE_PX:
            new_path = f"{os.path.splitext(path)[0]}_resized.jpg"
            # Save with compression - use lower quality if file is very large
            quality = COMPRESSION_QUALITY
            if file_size_mb > 5:  # If original file > 5MB, use more compression
                quality = 60
            elif file_size_mb > 2:  # If original file > 2MB, use moderate compression
                quality = 70
            
            img.save(new_path, 'JPEG', quality=quality, optimize=True)
            
            # Verify the resized file is reasonable
            new_size_mb = os.path.getsize(new_path) / (1024 * 1024)
            if new_size_mb > 5:  # If still too large, compress more
                img.save(new_path, 'JPEG', quality=50, optimize=True)
            
            return new_path
        
        return path
    except Exception as e:
        print(f"Image resize error for {path}: {e}")
        import traceback
        traceback.print_exc()
        # Return original path as fallback, but log the error
        return path


def convert_pdf_to_images(pdf_path):
    """Convert PDF to images (one page = one image)."""
    if not PDF2IMAGE_AVAILABLE:
        print("PDF2IMAGE not available. Cannot convert PDF.")
        return []
    
    try:
        if not pdf_path or not os.path.exists(pdf_path):
            return []
        
        # Convert PDF pages to images
        images = convert_from_path(pdf_path, dpi=200)
        image_paths = []
        
        base_path = os.path.splitext(pdf_path)[0]
        
        for i, img in enumerate(images):
            # Convert to RGB if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            
            # Resize if too large
            w, h = img.size
            if w > MAX_IMAGE_PX or h > MAX_IMAGE_PX:
                ratio = min(MAX_IMAGE_PX / float(w), MAX_IMAGE_PX / float(h))
                new_size = (int(w * ratio), int(h * ratio))
                img = img.resize(new_size, PILImage.LANCZOS)
            
            # Save as JPEG with compression
            image_path = f"{base_path}_page_{i+1}.jpg"
            img.save(image_path, 'JPEG', quality=COMPRESSION_QUALITY, optimize=True)
            image_paths.append(image_path)
        
        return image_paths
    except Exception as e:
        logger.error(f"PDF to image conversion error for {pdf_path}: {e}", exc_info=True)
        return []


def image_flowable(path, max_width_inch=MAX_IMAGE_WIDTH_INCH):
    """Return ReportLab Image flowable scaled to max width."""
    if not path or not os.path.exists(path):
        return None
    try:
        # Ensure image is resized first (in case it wasn't already)
        resized_path = ensure_image_resized(path)
        if not resized_path:
            return None
        
        max_w_pts = max_width_inch * 72
        img = Image(resized_path)
        iw, ih = img.drawWidth, img.drawHeight
        
        # Additional safety check - if still too large, scale down
        if iw > max_w_pts:
            scale = max_w_pts / iw
            img.drawWidth *= scale
            img.drawHeight *= scale
        
        # Ensure reasonable size limits (max 8 inches height)
        max_h_pts = 8 * 72
        if img.drawHeight > max_h_pts:
            scale = max_h_pts / img.drawHeight
            img.drawWidth *= scale
            img.drawHeight *= scale
        
        img.hAlign = 'CENTER'
        return img
    except Exception as e:
        logger.error(f"Error creating image flowable for {path}: {e}", exc_info=True)
        return None


def format_synopsis_text(text, format_type="plain"):
    """Format synopsis text based on format type (plain, bullet, numbered)"""
    if not text:
        return ""
    
    text = text.strip()
    if format_type == "plain":
        return text
    
    # Split by newlines
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    
    if format_type == "bullet":
        # Format as bullet points
        formatted_lines = []
        for line in lines:
            formatted_lines.append(f"• {line}")
        return '\n'.join(formatted_lines)
    
    elif format_type == "numbered":
        # Format as numbered list
        formatted_lines = []
        for i, line in enumerate(lines, 1):
            formatted_lines.append(f"{i}. {line}")
        return '\n'.join(formatted_lines)
    
    return text

def make_table_from_dict(dct, colWidths=[2.5 * inch, 4.5 * inch]):
    """Create a consistent table layout for key-value pairs."""
    if not dct:
        return []
    data = []
    for k, v in dct.items():
        keyp = Paragraph(str(k), styles['TableKey'])
        # Escape HTML and preserve newlines for formatted text
        v_escaped = str(v).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        # Convert newlines to <br/> for ReportLab
        v_escaped = v_escaped.replace('\n', '<br/>')
        valp = Paragraph(v_escaped, styles['TableValue'])
        data.append([keyp, valp])
    tbl = Table(data, colWidths=colWidths, hAlign='LEFT')
    tbl.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    return [tbl, Spacer(1, 0.12 * inch)]


def format_date_and_time(info):
    """Format date/time fields for single or multi-day display."""
    start_date = info.get("Start Date", "")
    end_date = info.get("End Date", "")
    start_time = info.get("Start Time", "")
    end_time = info.get("End Time", "")

    date_str = ""
    if start_date and end_date:
        if start_date == end_date:
            date_str = f"{format_date_label(start_date)}"
        else:
            date_str = f"{format_date_label(start_date)} – {format_date_label(end_date)}"
    elif start_date:
        date_str = format_date_label(start_date)

    time_str = ""
    if start_time and end_time:
        if start_time == end_time:
            time_str = start_time
        else:
            time_str = f"{start_time} – {end_time}"
    elif start_time:
        time_str = start_time

    if date_str:
        info["Date/s"] = date_str
    if time_str:
        info["Time"] = time_str

    for key in ["Start Date", "End Date", "Start Time", "End Time"]:
        info.pop(key, None)


def format_date_label(date_text):
    """Convert YYYY-MM-DD to readable date format."""
    try:
        dt = datetime.strptime(date_text, "%Y-%m-%d")
        return dt.strftime("%d %B %Y")
    except Exception:
        return date_text


# =============================
# PAGE NUMBERING
# =============================

def add_page_number(canvas, doc):
    """Add page number bottom-right."""
    page_num = canvas.getPageNumber()
    text = f"Page {page_num}"
    canvas.setFont(BASE_FONT, 10)
    canvas.drawRightString(8.0 * inch, 0.5 * inch, text)


# =============================
# MAIN PDF GENERATION
# =============================

def generate_report_pdf(data):
    """Generate PDF report with comprehensive error handling"""
    try:
        logger.info("Starting PDF report generation")
        buffer = BytesIO()
        story = []

        # HEADER
        try:
            story.append(Paragraph("CHRIST (Deemed to be University), Bangalore", styles['HeaderMain']))
            story.append(Paragraph("School of Engineering and Technology", styles['HeaderSub']))
            story.append(Paragraph("Department of AI, ML & Data Science", styles['HeaderSub']))
            story.append(Spacer(1, 0.3 * inch))
            story.append(Paragraph("<b>Activity Report</b>", styles['CenteredBold']))
            story.append(Spacer(1, 0.2 * inch))
        except Exception as e:
            logger.error(f"Error creating header: {e}", exc_info=True)
            raise

        # GENERAL INFORMATION
        story.append(Paragraph("General Information", styles['SectionTitle']))
        general_info = data.get("general_info", {})
        format_date_and_time(general_info)
        story.extend(make_table_from_dict(general_info))

        # SPEAKER DETAILS
        story.append(Paragraph("Speaker/Guest/Presenter Details", styles['SectionTitle']))
        for sp in data.get("speakers", []):
            speaker_info = {
                "Name": sp.get("name", ""),
                "Title/Position": sp.get("title", ""),
                "Organization": sp.get("organization", ""),
                "Contact Info": sp.get("contact", ""),
                "Title of Presentation": sp.get("presentation_title", "")
            }
            story.extend(make_table_from_dict(speaker_info))

        # PARTICIPANTS
        story.append(Paragraph("Participants profile", styles['SectionTitle']))
        for p in data.get("participants", []):
            pdata = {
                "Type of Participants": p.get("type", ""),
                "No. of Participants": p.get("count", "")
            }
            story.extend(make_table_from_dict(pdata))

        # SYNOPSIS (TABLE FORMAT)
        story.append(Paragraph("Synopsis of the Activity (Description)", styles['SectionTitle']))
        synopsis = data.get("synopsis", {})
        syn_dict = {}
        
        # Format highlights
        if synopsis.get("highlights"):
            highlights_text = format_synopsis_text(
                synopsis["highlights"], 
                synopsis.get("highlights_format", "plain")
            )
            syn_dict["Highlights of the Activity"] = highlights_text
        
        # Format key takeaways
        if synopsis.get("key_takeaways"):
            takeaways_text = format_synopsis_text(
                synopsis["key_takeaways"],
                synopsis.get("key_takeaways_format", "plain")
            )
            syn_dict["Key Takeaways"] = takeaways_text
        
        # Format summary
        if synopsis.get("summary"):
            summary_text = format_synopsis_text(
                synopsis["summary"],
                synopsis.get("summary_format", "plain")
            )
            syn_dict["Summary of the Activity"] = summary_text
        
        # Format follow-up
        if synopsis.get("follow_up"):
            followup_text = format_synopsis_text(
                synopsis["follow_up"],
                synopsis.get("follow_up_format", "plain")
            )
            syn_dict["Follow-up plan"] = followup_text
        
        story.extend(make_table_from_dict(syn_dict))

        # REPORT PREPARED BY
        story.append(Paragraph("Report prepared by", styles['SectionTitle']))
        for p in data.get("preparers", []):
            pdata = {
                "Name of the Organiser": p.get("name", ""),
                "Designation/Title": p.get("designation", "")
            }
            story.extend(make_table_from_dict(pdata))
            if p.get("signature_path"):
                sig = image_flowable(p.get("signature_path"), 1.5)
                if sig:
                    story.append(Paragraph("Digital Signature:", styles['TableKey']))
                    story.append(sig)
                    story.append(Spacer(1, 0.2 * inch))

        # SPEAKER PROFILE
        story.append(Paragraph("Speaker Profile", styles['SectionTitle']))
        profile = data.get("speaker_profile", {})
        if profile.get("bio"):
            story.append(Paragraph(profile["bio"], styles['NormalText']))
            story.append(Spacer(1, 0.15 * inch))
        if profile.get("image_path"):
            img = image_flowable(profile["image_path"], 2.5)
            if img:
                story.append(img)
                story.append(Spacer(1, 0.15 * inch))

        # PHOTOS SECTION
        photos = data.get("photos", [])
        if photos:
            story.append(PageBreak())
            title = general_info.get("Activity Type", "")
            date_display = general_info.get("Date/s", "")
            story.append(Paragraph("Photos of the activity", styles["PhotoHeading"]))
            if title and date_display:
                story.append(Paragraph(f"({title} – {date_display})", styles["PhotoHeading"]))
            story.append(Spacer(1, 0.2 * inch))

            for p in photos:
                img = image_flowable(p)
                if img:
                    story.append(img)
                    story.append(Spacer(1, 0.25 * inch))
        else:
            story.append(Paragraph("No photos available.", styles["NormalText"]))

        # NEW SECTIONS: Attendance List, Brochure, Notice, Feedback, Impact
        # These sections appear after the photos section
        section_titles = {
            'attendance_list': 'Attendance List',
            'brochure': 'Brochure',
            'notice': 'Notice for Approval',
            'feedback': 'Feedback Analysis',
            'impact': 'Impact Analysis'
        }
        
        # Process each section and add to PDF if files are present
        for section_key, section_title in section_titles.items():
            section_files = data.get(section_key, [])
            if section_files and len(section_files) > 0:
                # Add page break before each new section
                story.append(PageBreak())
                story.append(Paragraph(section_title, styles["PhotoHeading"]))
                story.append(Spacer(1, 0.2 * inch))
                
                # Add each file/image in the section
                for file_path in section_files:
                    if file_path:  # Ensure file path exists
                        img = image_flowable(file_path)
                        if img:
                            story.append(img)
                            story.append(Spacer(1, 0.25 * inch))

        # BUILD
        try:
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                leftMargin=0.9 * inch,
                rightMargin=0.9 * inch,
                topMargin=0.9 * inch,
                bottomMargin=0.9 * inch
            )
            doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
            pdf = buffer.getvalue()
            buffer.close()
            logger.info(f"PDF built successfully, size: {len(pdf)} bytes")
        except Exception as e:
            buffer.close()
            logger.error(f"Error building PDF: {e}", exc_info=True)
            raise

        # construct filename like Workshop_Title_Date.pdf
        try:
            title_words = (
                general_info.get("Title of the Activity", "Activity")
                .replace(":", "")
                .replace("/", "")
                .replace(" ", "")
            )
            date_field = general_info.get("Date/s", "").replace(" ", "").replace("–", "_")
            filename = f"Workshop_{title_words}_{date_field}.pdf"
        except Exception as e:
            logger.warning(f"Error constructing filename: {e}, using default")
            filename = f"ActivityReport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        logger.info(f"Report generated successfully: {filename}")
        return pdf, filename
        
    except Exception as e:
        logger.error(f"Critical error in generate_report_pdf: {e}", exc_info=True)
        raise
