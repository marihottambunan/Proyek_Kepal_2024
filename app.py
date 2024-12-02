from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from PyPDF2 import PdfReader, PdfWriter
import base64
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'rahasia123'  # untuk flash messages

# Konfigurasi upload folder
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def embed_message(input_pdf, output_pdf, message, key):
    try:
        reader = PdfReader(input_pdf)
        writer = PdfWriter()
        
        # Enkripsi pesan
        message_bytes = message.encode('utf-8')
        encoded_message = base64.b64encode(message_bytes).decode('utf-8')
        
        # Metadata dan enkripsi XOR
        metadata = reader.metadata.copy() if reader.metadata else {}
        encrypted = ''
        for i in range(len(encoded_message)):
            encrypted += chr(ord(encoded_message[i]) ^ ord(key[i % len(key)]))
        
        metadata['/Secret'] = encrypted
        
        # Salin halaman dan tambah metadata
        for page in reader.pages:
            writer.add_page(page)
        
        writer.add_metadata(metadata)
        
        # Simpan PDF
        with open(output_pdf, 'wb') as output_file:
            writer.write(output_file)
        return True
    except Exception as e:
        print(f"Error in embed_message: {str(e)}")
        return False

def extract_message(input_pdf, key):
    try:
        reader = PdfReader(input_pdf)
        metadata = reader.metadata
        
        if metadata is None or '/Secret' not in metadata:
            return "Tidak ada pesan tersembunyi"
        
        encrypted = metadata['/Secret']
        
        # Dekripsi XOR
        decrypted = ''
        for i in range(len(encrypted)):
            decrypted += chr(ord(encrypted[i]) ^ ord(key[i % len(key)]))
        
        # Decode base64
        message_bytes = base64.b64decode(decrypted)
        return message_bytes.decode('utf-8')
    except Exception as e:
        return f"Gagal mengekstrak pesan: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/embed', methods=['POST'])
def embed():
    if 'file' not in request.files:
        flash('Tidak ada file yang dipilih')
        return redirect(url_for('index'))
    
    file = request.files['file']
    message = request.form.get('message', '')
    key = request.form.get('key', '')
    
    if file.filename == '':
        flash('Tidak ada file yang dipilih')
        return redirect(url_for('index'))
    
    if not message or not key:
        flash('Pesan dan kunci harus diisi')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        # Simpan file input
        input_filename = secure_filename(file.filename)
        input_path = os.path.join(app.config['UPLOAD_FOLDER'], input_filename)
        file.save(input_path)
        
        # Generate nama file output
        output_filename = 'stego_' + input_filename
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        
        # Proses embedding
        if embed_message(input_path, output_path, message, key):
            # Hapus file input
            os.remove(input_path)
            return send_file(output_path, as_attachment=True, download_name=output_filename)
        else:
            flash('Gagal menyisipkan pesan')
            return redirect(url_for('index'))
    
    flash('Format file tidak diizinkan')
    return redirect(url_for('index'))

@app.route('/extract', methods=['POST'])
def extract():
    if 'file' not in request.files:
        flash('Tidak ada file yang dipilih')
        return redirect(url_for('index'))
    
    file = request.files['file']
    key = request.form.get('key', '')
    
    if file.filename == '':
        flash('Tidak ada file yang dipilih')
        return redirect(url_for('index'))
    
    if not key:
        flash('Kunci harus diisi')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        # Simpan file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Ekstrak pesan
        message = extract_message(filepath, key)
        
        # Hapus file
        os.remove(filepath)
        
        return render_template('result.html', message=message)
    
    flash('Format file tidak diizinkan')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)