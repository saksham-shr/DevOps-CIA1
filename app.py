import os
from flask import Flask, render_template, request, send_file, redirect, url_for, jsonify, session, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.utils import secure_filename
from report_logic import generate_report_pdf, ensure_image_resized, convert_pdf_to_images
from io import BytesIO
import time
import re
import json
import hashlib
from database import (
    init_db, create_user, verify_user, get_user_by_email, get_user_by_id,
    save_draft, get_user_drafts, get_draft, get_draft_by_id, delete_draft,
    log_login_session, check_device, create_password_reset_token, verify_reset_token, use_reset_token,
    get_new_device_logins, get_all_login_sessions, get_user_login_sessions,
    save_signature, get_user_signatures, get_signature, delete_signature, set_default_signature,
    log_unauthorized_access, get_unauthorized_access_logs,
    add_collaborator, get_draft_collaborators, get_user_collaborative_drafts, remove_collaborator, can_edit_draft
)
from config import ALLOWED_EMAILS, ADMIN_EMAIL, SECRET_KEY, DEMO_MODE, DEMO_EMAIL, DEMO_PASSWORD
from geolocation import get_location_from_ip, format_location_string
from logging_config import setup_logging

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
app.config['SECRET_KEY'] = SECRET_KEY
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Setup logging
logger = setup_logging(app)
app.logger.info("Application initialized")

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

ALLOWED_IMAGE_EXTS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_PDF_EXTS = {'pdf'}

class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_id(user_id)
    if user_data:
        return User(user_data['id'], user_data['email'])
    return None

# Demo mode decorator
def demo_or_login_required(f):
    """Decorator that allows access in demo mode or requires login"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if DEMO_MODE:
            # In demo mode, create a demo user if not logged in
            if not current_user.is_authenticated:
                # Create demo user if it doesn't exist
                demo_user_data = get_user_by_email(DEMO_EMAIL)
                if not demo_user_data:
                    create_user(DEMO_EMAIL, DEMO_PASSWORD)
                    demo_user_data = get_user_by_email(DEMO_EMAIL)
                if demo_user_data:
                    user = User(demo_user_data['id'], demo_user_data['email'])
                    login_user(user)
            return f(*args, **kwargs)
        else:
            # Normal mode - require login
            return login_required(f)(*args, **kwargs)
    return decorated_function

def get_device_fingerprint():
    """Generate device fingerprint from user agent and IP"""
    user_agent = request.headers.get('User-Agent', '')
    ip_address = request.remote_addr
    fingerprint_string = f"{user_agent}_{ip_address}"
    return hashlib.md5(fingerprint_string.encode()).hexdigest()

def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set

def save_uploaded_file(fileobj, subfolder=None, allow_pdf=False):
    if not fileobj or fileobj.filename == '':
        return None
    
    ext = fileobj.filename.rsplit('.', 1)[1].lower() if '.' in fileobj.filename else ''
    allowed_set = ALLOWED_IMAGE_EXTS
    if allow_pdf and ext == 'pdf':
        allowed_set = ALLOWED_IMAGE_EXTS | ALLOWED_PDF_EXTS
    
    if not allowed_file(fileobj.filename, allowed_set):
        return None
    
    filename = secure_filename(fileobj.filename)
    ts = int(time.time() * 1000)
    name = f"{ts}_{filename}"
    dest_dir = app.config['UPLOAD_FOLDER'] if not subfolder else os.path.join(app.config['UPLOAD_FOLDER'], subfolder)
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, name)
    fileobj.save(path)
    return path

@app.route('/')
def landing():
    """Landing page"""
    if DEMO_MODE:
        # In demo mode, redirect directly to report generator
        return redirect(url_for('report'))
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        
        # Allow any email but track if not in whitelist
        is_authorized = email in [e.lower() for e in ALLOWED_EMAILS]
        if not is_authorized:
            # Log unauthorized login attempt
            location_data = get_location_from_ip(request.remote_addr)
            log_unauthorized_access(email, request.remote_addr, request.headers.get('User-Agent', ''), 
                                  'login_attempt', location_data)
            print(f"WARNING: Unauthorized login attempt from {email} at {request.remote_addr}")
        
        # Check if this is admin email
        is_admin_email = email.lower() == ADMIN_EMAIL.lower()
        
        user_data = verify_user(email, password)
        if user_data:
            # Additional logging for admin login
            if is_admin_email:
                app.logger.info(f"Admin login attempt: {email}")
            
            user = User(user_data['id'], user_data['email'])
            login_user(user)
            
            # Device tracking
            device_fingerprint = get_device_fingerprint()
            device_info = request.headers.get('User-Agent', 'Unknown')
            ip_address = request.remote_addr
            
            # Get location from IP
            location_data = get_location_from_ip(ip_address)
            
            is_known, is_new = check_device(user_data['id'], device_fingerprint, device_info)
            log_login_session(user_data['id'], device_info, ip_address, request.headers.get('User-Agent', ''), 1 if is_new else 0, location_data)
            
            if is_new:
                # Send alert to admin (you can implement email sending here)
                location_str = format_location_string(location_data) if location_data else "Unknown location"
                app.logger.warning(f"New device login for {email} from {ip_address} ({location_str})")
            
            if is_admin_email:
                app.logger.info(f"Admin successfully logged in: {email}")
                flash('Admin login successful!', 'success')
            else:
                flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            if is_admin_email:
                app.logger.warning(f"Failed admin login attempt: {email}")
            flash('Invalid email or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration - only for allowed emails"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Allow any email but track if not in whitelist
        is_authorized = email in [e.lower() for e in ALLOWED_EMAILS]
        if not is_authorized:
            # Log unauthorized registration attempt
            location_data = get_location_from_ip(request.remote_addr)
            log_unauthorized_access(email, request.remote_addr, request.headers.get('User-Agent', ''), 
                                  'registration_attempt', location_data)
            # Still allow registration but log it
            print(f"WARNING: Unauthorized registration attempt from {email} at {request.remote_addr}")
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html')
        
        user_id = create_user(email, password)
        if user_id:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email already registered. Please log in.', 'error')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('landing'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset request"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if email not in [e.lower() for e in ALLOWED_EMAILS]:
            flash('Access denied. This email is not authorized.', 'error')
            return render_template('forgot_password.html')
        
        user_data = get_user_by_email(email)
        if user_data:
            token = create_password_reset_token(user_data['id'])
            reset_link = url_for('reset_password', token=token, _external=True)
            # In production, send email here
            print(f"Password reset link for {email}: {reset_link}")
            flash('Password reset link has been sent to your email (check console in dev mode).', 'info')
        else:
            flash('Email not found.', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Password reset with token"""
    token_record = verify_reset_token(token)
    if not token_record:
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('reset_password.html', token=token)
        
        if use_reset_token(token, password):
            flash('Password reset successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Error resetting password. Please try again.', 'error')
    
    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
@demo_or_login_required
def dashboard():
    """Dashboard with draft management"""
    drafts = get_user_drafts(current_user.id)
    collaborative_drafts = get_user_collaborative_drafts(current_user.id)
    is_admin = current_user.email.lower() == ADMIN_EMAIL.lower()
    return render_template('dashboard.html', drafts=drafts, collaborative_drafts=collaborative_drafts, is_admin=is_admin)

@app.route('/new-report')
@demo_or_login_required
def new_report():
    """Start a new report"""
    return redirect(url_for('report'))

@app.route('/load-draft/<int:draft_id>')
@login_required
def load_draft(draft_id):
    """Load a saved draft"""
    # Check if user can access this draft
    if not can_edit_draft(draft_id, current_user.id):
        flash('You do not have access to this draft.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get draft (can be owned or collaborative)
    from database import get_draft_by_id
    draft = get_draft_by_id(draft_id)
    if not draft:
        flash('Draft not found.', 'error')
        return redirect(url_for('dashboard'))
    
    form_data = json.loads(draft['form_data'])
    saved_signatures = get_user_signatures(current_user.id)
    collaborators = get_draft_collaborators(draft_id)
    is_owner = draft['user_id'] == current_user.id
    return render_template('index.html', draft_data=form_data, draft_id=draft_id, saved_signatures=saved_signatures, collaborators=collaborators, is_owner=is_owner)

@app.route('/delete-draft/<int:draft_id>', methods=['POST'])
@login_required
def delete_draft_route(draft_id):
    """Delete a draft"""
    delete_draft(draft_id, current_user.id)
    flash('Draft deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/save_draft', methods=['POST'])
@login_required
def save_draft_route():
    """Save draft endpoint"""
    try:
        form_data = {}
        
        # Collect all form data
        for key, value in request.form.items():
            if key not in ['action', 'section']:
                form_data[key] = value
        
        # Collect file information (we'll save file paths)
        file_data = {}
        for key in request.files:
            file = request.files[key]
            if file and file.filename:
                # Save file temporarily
                subfolder_map = {
                    'preparer-signature': 'signatures',
                    'speakerImage': 'speaker',
                    'photo': 'photos',
                    'attendance': 'attendance',
                    'brochure': 'brochure',
                    'notice': 'notice',
                    'feedback': 'feedback',
                    'impact': 'impact'
                }
                subfolder = None
                for prefix, folder in subfolder_map.items():
                    if key.startswith(prefix):
                        subfolder = folder
                        break
                
                file_path = save_uploaded_file(file, subfolder=subfolder, allow_pdf=True)
                if file_path:
                    file_data[key] = file_path
        
        form_data.update(file_data)
        
        section = request.form.get('section', 'general-info')
        draft_name = f"Draft - {section} - {time.strftime('%Y-%m-%d %H:%M')}"
        
        draft_id = save_draft(current_user.id, draft_name, form_data)
        return jsonify({'success': True, 'draft_id': draft_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/save-signature', methods=['POST'])
@login_required
def save_signature_route():
    """Save a signature"""
    try:
        sig_file = request.files.get('signature')
        signature_name = request.form.get('signature_name', '').strip()
        set_as_default = request.form.get('set_as_default') == 'on'
        
        if not sig_file or not sig_file.filename:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        sig_path = save_uploaded_file(sig_file, subfolder='signatures')
        if sig_path:
            sig_path = ensure_image_resized(sig_path)
            signature_id = save_signature(current_user.id, sig_path, signature_name, set_as_default)
            return jsonify({'success': True, 'signature_id': signature_id})
        else:
            return jsonify({'success': False, 'error': 'Failed to save file'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/delete-signature/<int:signature_id>', methods=['POST'])
@login_required
def delete_signature_route(signature_id):
    """Delete a signature"""
    delete_signature(signature_id, current_user.id)
    flash('Signature deleted successfully.', 'success')
    return redirect(url_for('report'))

@app.route('/set-default-signature/<int:signature_id>', methods=['POST'])
@login_required
def set_default_signature_route(signature_id):
    """Set a signature as default"""
    set_default_signature(signature_id, current_user.id)
    flash('Default signature updated.', 'success')
    return redirect(url_for('report'))

@app.route('/report', methods=['GET', 'POST'])
@demo_or_login_required
def report():
    """Report generator page"""
    # Get saved signatures for the user
    saved_signatures = get_user_signatures(current_user.id)
    
    if request.method == 'POST':
        try:
            data = {}

            # General Information
            data['general_info'] = {
                'Title of the Activity': request.form.get('activityTitle', '').strip(),
                'Activity Type': request.form.get('activityType', ''),
                'Sub Category': request.form.get('subCategory', '') or request.form.get('otherSubCategory', ''),
                'Start Date': request.form.get('startDate', ''),
                'End Date': request.form.get('endDate', ''),
                'Start Time': request.form.get('startTime', ''),
                'End Time': request.form.get('endTime', ''),
                'Venue': request.form.get('venue', ''),
                'Collaboration/Sponsor': request.form.get('collaboration', '')
            }
            data['general_info'] = {k: v for k, v in data['general_info'].items() if v}

            # Extract multiple speakers
            speakers = []
            speaker_index = 0
            while True:
                name_key = f'speaker-name-{speaker_index}'
                if name_key not in request.form:
                    break
                speaker_name = request.form.get(name_key, '').strip()
                if speaker_name:
                    speaker = {
                        'name': speaker_name,
                        'title': request.form.get(f'speaker-title-{speaker_index}', '').strip(),
                        'organization': request.form.get(f'speaker-org-{speaker_index}', '').strip(),
                        'contact': request.form.get(f'speaker-contact-{speaker_index}', '').strip(),
                        'presentation_title': request.form.get(f'speaker-presentation-{speaker_index}', '').strip()
                    }
                    speakers.append(speaker)
                speaker_index += 1
            data['speakers'] = speakers

            # Extract multiple participants
            participants = []
            participant_index = 0
            while True:
                type_key = f'participant-type-{participant_index}'
                if type_key not in request.form:
                    break
                participant_type = request.form.get(type_key, '').strip()
                if participant_type:
                    count = request.form.get(f'participant-count-{participant_index}', '0').strip()
                    participant = {'type': participant_type, 'count': count}
                    participants.append(participant)
                participant_index += 1
            data['participants'] = participants

            # Synopsis with formatting options
            data['synopsis'] = {
                'highlights': request.form.get('highlights', '').strip(),
                'highlights_format': request.form.get('highlights-format', 'plain'),
                'key_takeaways': request.form.get('keyTakeaways', '').strip(),
                'key_takeaways_format': request.form.get('keyTakeaways-format', 'plain'),
                'summary': request.form.get('summary', '').strip(),
                'summary_format': request.form.get('summary-format', 'plain'),
                'follow_up': request.form.get('followUp', '').strip(),
                'follow_up_format': request.form.get('followUp-format', 'plain')
            }

            # Extract multiple preparers
            preparers = []
            preparer_index = 0
            while True:
                name_key = f'preparer-name-{preparer_index}'
                if name_key not in request.form:
                    break
                preparer_name = request.form.get(name_key, '').strip()
                if preparer_name:
                    preparer = {
                        'name': preparer_name,
                        'designation': request.form.get(f'preparer-designation-{preparer_index}', '').strip(),
                        'signature_path': None
                    }
                    # Check if using saved signature
                    saved_sig_id = request.form.get(f'preparer-signature-saved-{preparer_index}')
                    if saved_sig_id and saved_sig_id != 'none':
                        sig_data = get_signature(int(saved_sig_id), current_user.id)
                        if sig_data:
                            preparer['signature_path'] = sig_data['signature_path']
                    else:
                        # Check for uploaded file
                        sig_file = request.files.get(f'preparer-signature-{preparer_index}')
                        if sig_file and sig_file.filename:
                            sig_path = save_uploaded_file(sig_file, subfolder='signatures')
                            if sig_path:
                                preparer['signature_path'] = ensure_image_resized(sig_path)
                                # Optionally save this signature for future use
                                save_for_future = request.form.get(f'save-signature-{preparer_index}') == 'on'
                                if save_for_future:
                                    save_signature(current_user.id, preparer['signature_path'], 
                                                 f"{preparer_name} - {preparer['designation']}", False)
                    preparers.append(preparer)
                preparer_index += 1
            data['preparers'] = preparers

            # Speaker Profile
            speaker_profile = {}
            speaker_file = request.files.get('speakerImage')
            if speaker_file and speaker_file.filename:
                speaker_path = save_uploaded_file(speaker_file, subfolder='speaker')
                if speaker_path:
                    speaker_profile['image_path'] = ensure_image_resized(speaker_path)
            speaker_bio = request.form.get('speakerBio', '').strip()
            if speaker_bio:
                speaker_profile['bio'] = speaker_bio
            data['speaker_profile'] = speaker_profile

            # Activity Photos
            photos = []
            photo_index = 1
            while True:
                photo_key = f'photo{photo_index}'
                if photo_key not in request.files:
                    break
                photo_file = request.files.get(photo_key)
                if photo_file and photo_file.filename:
                    photo_path = save_uploaded_file(photo_file, subfolder='photos', allow_pdf=True)
                    if photo_path:
                        if photo_path.lower().endswith('.pdf'):
                            # Convert PDF to images
                            pdf_images = convert_pdf_to_images(photo_path)
                            photos.extend([ensure_image_resized(img) for img in pdf_images])
                        else:
                            photos.append(ensure_image_resized(photo_path))
                photo_index += 1
            data['photos'] = photos

            # New sections: Attendance List, Brochure, Notice, Feedback, Impact
            for section_name, subfolder in [
                ('attendance_list', 'attendance'),
                ('brochure', 'brochure'),
                ('notice', 'notice'),
                ('feedback', 'feedback'),
                ('impact', 'impact')
            ]:
                section_files = []
                index = 0
                while True:
                    file_key = f'{section_name.split("_")[0]}-{index}'
                    if file_key not in request.files:
                        break
                    file_obj = request.files.get(file_key)
                    if file_obj and file_obj.filename:
                        file_path = save_uploaded_file(file_obj, subfolder=subfolder, allow_pdf=True)
                        if file_path:
                            if file_path.lower().endswith('.pdf'):
                                pdf_images = convert_pdf_to_images(file_path)
                                section_files.extend([ensure_image_resized(img) for img in pdf_images])
                            else:
                                section_files.append(ensure_image_resized(file_path))
                    index += 1
                data[section_name] = section_files

            # Validate required fields
            errors = []
            if not data['general_info'].get('Activity Type'):
                errors.append("Activity Type is required")
            if not data['general_info'].get('Venue'):
                errors.append("Venue is required")
            if not speakers:
                errors.append("At least one speaker is required")
            if not participants:
                errors.append("At least one participant type is required")
            if not preparers:
                errors.append("At least one report preparer is required")
            if len(photos) < 2:
                errors.append("At least 2 activity photos are required")
            
            if errors:
                error_msg = "; ".join(errors)
                return render_template('index.html', error=error_msg, saved_signatures=saved_signatures)

            # Generate PDF
            pdf_bytes, filename = generate_report_pdf(data)
            return send_file(
                BytesIO(pdf_bytes),
                mimetype='application/pdf',
                as_attachment=True,
                download_name=filename
            )

        except Exception as exc:
            app.logger.error(f"Exception in report generation - User: {current_user.email}, Error: {exc}", exc_info=True)
            saved_signatures = get_user_signatures(current_user.id)
            return render_template('index.html', error=f"Error generating report: {str(exc)}", saved_signatures=saved_signatures)

    saved_signatures = get_user_signatures(current_user.id)
    return render_template('index.html', saved_signatures=saved_signatures)

@app.route('/privacy-policy')
def privacy_policy():
    """Privacy policy page"""
    return render_template('privacy_policy.html')

@app.route('/terms-of-use')
def terms_of_use():
    """Terms of use page"""
    return render_template('terms_of_use.html')

@app.route('/contact')
def contact():
    """Contact and help page"""
    return render_template('contact.html')

@app.route('/admin/locations')
@login_required
def admin_locations():
    """Admin view to see all user locations"""
    # Check if user is admin
    if current_user.email.lower() != ADMIN_EMAIL.lower():
        flash('Access denied. Admin access required.', 'error')
        return redirect(url_for('dashboard'))
    
    sessions = get_all_login_sessions(limit=200)
    
    # Format location data for display
    for session in sessions:
        if session.get('location_city'):
            session['location_str'] = format_location_string({
                'city': session.get('location_city'),
                'region': session.get('location_region'),
                'country': session.get('location_country')
            })
        else:
            session['location_str'] = 'Location unknown'
    
    return render_template('admin_locations.html', sessions=sessions)

@app.route('/preview-report', methods=['POST'])
@demo_or_login_required
def preview_report():
    """Generate a live preview of the report"""
    try:
        data = {}

        # General Information
        data['general_info'] = {
            'Title of the Activity': request.form.get('activityTitle', '').strip(),
            'Activity Type': request.form.get('activityType', ''),
            'Sub Category': request.form.get('subCategory', '') or request.form.get('otherSubCategory', ''),
            'Start Date': request.form.get('startDate', ''),
            'End Date': request.form.get('endDate', ''),
            'Start Time': request.form.get('startTime', ''),
            'End Time': request.form.get('endTime', ''),
            'Venue': request.form.get('venue', ''),
            'Collaboration/Sponsor': request.form.get('collaboration', '')
        }
        data['general_info'] = {k: v for k, v in data['general_info'].items() if v}

        # Extract multiple speakers
        speakers = []
        speaker_index = 0
        while True:
            name_key = f'speaker-name-{speaker_index}'
            if name_key not in request.form:
                break
            speaker_name = request.form.get(name_key, '').strip()
            if speaker_name:
                speaker = {
                    'name': speaker_name,
                    'title': request.form.get(f'speaker-title-{speaker_index}', '').strip(),
                    'organization': request.form.get(f'speaker-org-{speaker_index}', '').strip(),
                    'contact': request.form.get(f'speaker-contact-{speaker_index}', '').strip(),
                    'presentation_title': request.form.get(f'speaker-presentation-{speaker_index}', '').strip()
                }
                speakers.append(speaker)
            speaker_index += 1
        data['speakers'] = speakers

        # Extract multiple participants
        participants = []
        participant_index = 0
        while True:
            type_key = f'participant-type-{participant_index}'
            if type_key not in request.form:
                break
            participant_type = request.form.get(type_key, '').strip()
            if participant_type:
                count = request.form.get(f'participant-count-{participant_index}', '0').strip()
                participant = {'type': participant_type, 'count': count}
                participants.append(participant)
            participant_index += 1
        data['participants'] = participants

        # Synopsis with formatting options
        data['synopsis'] = {
            'highlights': request.form.get('highlights', '').strip(),
            'highlights_format': request.form.get('highlights-format', 'plain'),
            'key_takeaways': request.form.get('keyTakeaways', '').strip(),
            'key_takeaways_format': request.form.get('keyTakeaways-format', 'plain'),
            'summary': request.form.get('summary', '').strip(),
            'summary_format': request.form.get('summary-format', 'plain'),
            'follow_up': request.form.get('followUp', '').strip(),
            'follow_up_format': request.form.get('followUp-format', 'plain')
        }

        # Extract multiple preparers
        preparers = []
        preparer_index = 0
        while True:
            name_key = f'preparer-name-{preparer_index}'
            if name_key not in request.form:
                break
            preparer_name = request.form.get(name_key, '').strip()
            if preparer_name:
                preparer = {
                    'name': preparer_name,
                    'designation': request.form.get(f'preparer-designation-{preparer_index}', '').strip(),
                    'signature_path': None
                }
                # Check if using saved signature
                saved_sig_id = request.form.get(f'preparer-signature-saved-{preparer_index}')
                if saved_sig_id and saved_sig_id != 'none':
                    user_id = current_user.id if current_user.is_authenticated else None
                    if user_id:
                        sig_data = get_signature(int(saved_sig_id), user_id)
                        if sig_data:
                            preparer['signature_path'] = sig_data['signature_path']
                else:
                    # Check for uploaded file
                    sig_file = request.files.get(f'preparer-signature-{preparer_index}')
                    if sig_file and sig_file.filename:
                        sig_path = save_uploaded_file(sig_file, subfolder='signatures')
                        if sig_path:
                            preparer['signature_path'] = ensure_image_resized(sig_path)
                preparers.append(preparer)
            preparer_index += 1
        data['preparers'] = preparers

        # Speaker Profile
        speaker_profile = {}
        speaker_file = request.files.get('speakerImage')
        if speaker_file and speaker_file.filename:
            speaker_path = save_uploaded_file(speaker_file, subfolder='speaker')
            if speaker_path:
                speaker_profile['image_path'] = ensure_image_resized(speaker_path)
        speaker_bio = request.form.get('speakerBio', '').strip()
        if speaker_bio:
            speaker_profile['bio'] = speaker_bio
        data['speaker_profile'] = speaker_profile

        # Activity Photos (with PDF support)
        photos = []
        photo_index = 1
        while True:
            photo_key = f'photo{photo_index}'
            if photo_key not in request.files:
                break
            photo_file = request.files.get(photo_key)
            if photo_file and photo_file.filename:
                photo_path = save_uploaded_file(photo_file, subfolder='photos', allow_pdf=True)
                if photo_path:
                    if photo_path.lower().endswith('.pdf'):
                        # Convert PDF to images (one page = one image)
                        pdf_images = convert_pdf_to_images(photo_path)
                        photos.extend([ensure_image_resized(img) for img in pdf_images])
                    else:
                        photos.append(ensure_image_resized(photo_path))
            photo_index += 1
        data['photos'] = photos

        # New sections: Attendance List, Brochure, Notice, Feedback, Impact (with PDF support)
        for section_name, subfolder in [
            ('attendance_list', 'attendance'),
            ('brochure', 'brochure'),
            ('notice', 'notice'),
            ('feedback', 'feedback'),
            ('impact', 'impact')
        ]:
            section_files = []
            index = 0
            while True:
                file_key = f'{section_name.split("_")[0]}-{index}'
                if file_key not in request.files:
                    break
                file_obj = request.files.get(file_key)
                if file_obj and file_obj.filename:
                    file_path = save_uploaded_file(file_obj, subfolder=subfolder, allow_pdf=True)
                    if file_path:
                        if file_path.lower().endswith('.pdf'):
                            # Convert PDF to images (one page = one image)
                            pdf_images = convert_pdf_to_images(file_path)
                            section_files.extend([ensure_image_resized(img) for img in pdf_images])
                        else:
                            section_files.append(ensure_image_resized(file_path))
                index += 1
            data[section_name] = section_files

        # Generate preview PDF
        pdf_bytes, filename = generate_report_pdf(data)
        
        # Convert to base64 for embedding
        import base64
        pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
        
        return jsonify({'success': True, 'pdf': pdf_base64})
    except Exception as e:
        import traceback
        app.logger.error(f"Preview generation error: {e}", exc_info=True)
        return jsonify({'success': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

@app.route('/add-collaborator/<int:draft_id>', methods=['POST'])
@login_required
def add_collaborator_route(draft_id):
    """Add a collaborator to a draft"""
    # Check if user owns the draft
    draft = get_draft_by_id(draft_id)
    if not draft or draft['user_id'] != current_user.id:
        flash('Only the draft owner can add collaborators.', 'error')
        return redirect(url_for('dashboard'))
    
    collaborator_email = request.form.get('email', '').strip().lower()
    if not collaborator_email:
        flash('Please provide an email address.', 'error')
        return redirect(url_for('load_draft', draft_id=draft_id))
    
    # Get collaborator user
    collaborator = get_user_by_email(collaborator_email)
    if not collaborator:
        flash('User not found. They must register first.', 'error')
        return redirect(url_for('load_draft', draft_id=draft_id))
    
    if add_collaborator(draft_id, collaborator['id']):
        flash(f'Collaborator {collaborator_email} added successfully.', 'success')
    else:
        flash('Collaborator already added or error occurred.', 'error')
    
    return redirect(url_for('load_draft', draft_id=draft_id))

@app.route('/remove-collaborator/<int:draft_id>/<int:user_id>', methods=['POST'])
@login_required
def remove_collaborator_route(draft_id, user_id):
    """Remove a collaborator from a draft"""
    # Check if user owns the draft
    draft = get_draft_by_id(draft_id)
    if not draft or draft['user_id'] != current_user.id:
        flash('Only the draft owner can remove collaborators.', 'error')
        return redirect(url_for('dashboard'))
    
    remove_collaborator(draft_id, user_id)
    flash('Collaborator removed successfully.', 'success')
    return redirect(url_for('load_draft', draft_id=draft_id))

@app.route('/admin')
@login_required
def admin_panel():
    """Main admin panel dashboard"""
    if current_user.email.lower() != ADMIN_EMAIL.lower():
        flash('Access denied. Admin access required.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get statistics
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    
    # Total users
    cursor.execute('SELECT COUNT(*) as count FROM users')
    total_users = cursor.fetchone()['count']
    
    # Total drafts
    cursor.execute('SELECT COUNT(*) as count FROM drafts')
    total_drafts = cursor.fetchone()['count']
    
    # Total login sessions
    cursor.execute('SELECT COUNT(*) as count FROM login_sessions')
    total_sessions = cursor.fetchone()['count']
    
    # Unauthorized access attempts
    cursor.execute('SELECT COUNT(*) as count FROM unauthorized_access')
    unauthorized_count = cursor.fetchone()['count']
    
    conn.close()
    
    return render_template('admin_panel.html', 
                         total_users=total_users,
                         total_drafts=total_drafts,
                         total_sessions=total_sessions,
                         unauthorized_count=unauthorized_count)

@app.route('/admin/users')
@login_required
def admin_users():
    """Admin view to see all users"""
    if current_user.email.lower() != ADMIN_EMAIL.lower():
        flash('Access denied. Admin access required.', 'error')
        return redirect(url_for('dashboard'))
    
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.*, 
               COUNT(DISTINCT d.id) as draft_count,
               COUNT(DISTINCT ls.id) as session_count,
               MAX(ls.login_time) as last_login
        FROM users u
        LEFT JOIN drafts d ON u.id = d.user_id
        LEFT JOIN login_sessions ls ON u.id = ls.user_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    ''')
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/stats')
@login_required
def admin_stats():
    """Admin view for system statistics"""
    if current_user.email.lower() != ADMIN_EMAIL.lower():
        flash('Access denied. Admin access required.', 'error')
        return redirect(url_for('dashboard'))
    
    from database import get_db
    conn = get_db()
    cursor = conn.cursor()
    
    # Get various statistics
    stats = {}
    
    # User stats
    cursor.execute('SELECT COUNT(*) as count FROM users')
    stats['total_users'] = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM users WHERE created_at > datetime("now", "-7 days")')
    stats['new_users_7d'] = cursor.fetchone()['count']
    
    # Draft stats
    cursor.execute('SELECT COUNT(*) as count FROM drafts')
    stats['total_drafts'] = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM drafts WHERE updated_at > datetime("now", "-7 days")')
    stats['active_drafts_7d'] = cursor.fetchone()['count']
    
    # Session stats
    cursor.execute('SELECT COUNT(*) as count FROM login_sessions')
    stats['total_sessions'] = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM login_sessions WHERE login_time > datetime("now", "-7 days")')
    stats['sessions_7d'] = cursor.fetchone()['count']
    
    # Security stats
    cursor.execute('SELECT COUNT(*) as count FROM unauthorized_access')
    stats['unauthorized_total'] = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM unauthorized_access WHERE attempt_time > datetime("now", "-7 days")')
    stats['unauthorized_7d'] = cursor.fetchone()['count']
    
    conn.close()
    
    return render_template('admin_stats.html', stats=stats)

@app.route('/admin/unauthorized-access')
@login_required
def admin_unauthorized_access():
    """Admin view to see unauthorized access attempts"""
    if current_user.email.lower() != ADMIN_EMAIL.lower():
        flash('Access denied. Admin access required.', 'error')
        return redirect(url_for('dashboard'))
    
    logs = get_unauthorized_access_logs(limit=200)
    return render_template('admin_unauthorized.html', logs=logs)

@app.route('/my-locations')
@login_required
def my_locations():
    """View own login locations"""
    sessions = get_user_login_sessions(current_user.id, limit=50)
    
    # Format location data for display
    for session in sessions:
        if session.get('location_city'):
            session['location_str'] = format_location_string({
                'city': session.get('location_city'),
                'region': session.get('location_region'),
                'country': session.get('location_country')
            })
        else:
            session['location_str'] = 'Location unknown'
    
    return render_template('my_locations.html', sessions=sessions)

if __name__ == '__main__':
    init_db()
    print("\n" + "="*60)
    print("Flask Application Starting...")
    print("="*60)
    print(f"\nAccess the application at:")
    print(f"  Local:   http://localhost:5000")
    print(f"  Network: http://127.0.0.1:5000")
    if DEMO_MODE:
        print(f"\nDemo Mode: ENABLED (No login required)")
    print("\n" + "="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
