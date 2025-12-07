import { useState } from 'react';
import axios from 'axios';
import { apiBaseURL } from '../utils/apiConfig';

export default function SteganographyTool() {
  const [image, setImage] = useState(null);
  const [imageSrc, setImageSrc] = useState('');
  const [text, setText] = useState('');
  const [hiddenText, setHiddenText] = useState('');
  const [encodedImage, setEncodedImage] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [mode, setMode] = useState('encode'); // encode or decode

  const handleImageUpload = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setImageSrc(event.target.result);
        setImage(event.target.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleEncode = async () => {
    if (!imageSrc || !text.trim()) {
      setMessage('⚠️ Please upload an image and enter text to hide');
      return;
    }

    setLoading(true);
    setMessage('🔄 Encoding text into image...');

    try {
      const response = await axios.post(`${apiBaseURL}/steganography/encode`, {
        image: imageSrc,
        text: text,
      });

      if (response.data.success) {
        setEncodedImage(response.data.encoded_image);
        setMessage(`✅ ${response.data.message}`);
      } else {
        setMessage(`❌ ${response.data.error}`);
      }
    } catch (error) {
      setMessage(`❌ Encoding failed: ${error.message}`);
    }

    setLoading(false);
  };

  const handleDecode = async () => {
    if (!imageSrc) {
      setMessage('⚠️ Please upload an image to extract hidden text');
      return;
    }

    setLoading(true);
    setMessage('🔄 Decoding hidden text...');

    try {
      const response = await axios.post(`${apiBaseURL}/steganography/decode`, {
        image: imageSrc,
      });

      if (response.data.success) {
        setHiddenText(response.data.hidden_text);
        setMessage(`✅ ${response.data.message}`);
      } else {
        setMessage(`⚠️ ${response.data.error}`);
      }
    } catch (error) {
      setMessage(`❌ Decoding failed: ${error.message}`);
    }

    setLoading(false);
  };

  const downloadImage = () => {
    if (encodedImage) {
      const link = document.createElement('a');
      link.href = encodedImage;
      link.download = 'hidden-message.png';
      link.click();
    }
  };

  return (
    <div className="tool-container stego-container">
      <h2 className="tool-title">🔒 Steganography Tool</h2>
      <p className="tool-description">
        Hide text inside images using LSB (Least Significant Bit) encoding. 
        Encode secret messages or extract hidden data from images.
      </p>

      {/* Mode Selector */}
      <div className="mode-selector">
        <button 
          className={`mode-btn ${mode === 'encode' ? 'active' : ''}`}
          onClick={() => { setMode('encode'); setMessage(''); setHiddenText(''); }}
        >
          🔐 Encode (Hide)
        </button>
        <button 
          className={`mode-btn ${mode === 'decode' ? 'active' : ''}`}
          onClick={() => { setMode('decode'); setMessage(''); setHiddenText(''); }}
        >
          🔓 Decode (Extract)
        </button>
      </div>

      {/* Image Upload */}
      <div className="stego-section">
        <h3>📷 Select Image</h3>
        <div className="image-upload-area">
          <input 
            type="file" 
            accept="image/*" 
            onChange={handleImageUpload}
            className="image-input"
          />
          <p className="upload-hint">PNG, JPG, or GIF recommended</p>
        </div>
      </div>

      {/* Image Preview */}
      {imageSrc && (
        <div className="image-preview-section">
          <h3>📸 Image Preview</h3>
          <img src={imageSrc} alt="Uploaded" className="preview-image" />
        </div>
      )}

      {/* Encode Mode */}
      {mode === 'encode' && (
        <div className="stego-section">
          <h3>✍️ Text to Hide</h3>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Enter the secret message (max 256 characters recommended)..."
            className="stego-textarea"
            maxLength={256}
          />
          <div className="char-count">{text.length}/256 characters</div>
          <button
            onClick={handleEncode}
            disabled={loading || !imageSrc || !text.trim()}
            className="btn-primary"
          >
            {loading ? '⏳ Encoding...' : '🔐 Hide Text in Image'}
          </button>
        </div>
      )}

      {/* Decode Mode */}
      {mode === 'decode' && (
        <div className="stego-section">
          <button
            onClick={handleDecode}
            disabled={loading || !imageSrc}
            className="btn-primary"
          >
            {loading ? '⏳ Decoding...' : '🔓 Extract Hidden Text'}
          </button>
        </div>
      )}

      {/* Results */}
      {message && <div className="message-box">{message}</div>}

      {encodedImage && mode === 'encode' && (
        <div className="stego-section">
          <h3>✅ Encoded Image</h3>
          <img src={encodedImage} alt="Encoded" className="preview-image" />
          <button onClick={downloadImage} className="btn-secondary">
            📥 Download Encoded Image
          </button>
        </div>
      )}

      {hiddenText && mode === 'decode' && (
        <div className="stego-section">
          <h3>🎉 Hidden Message Found!</h3>
          <div className="hidden-text-display">
            <p className="hidden-text-content">"{hiddenText}"</p>
          </div>
          <button 
            onClick={() => {
              navigator.clipboard.writeText(hiddenText);
              setMessage('✅ Copied to clipboard!');
            }}
            className="btn-secondary"
          >
            📋 Copy Text
          </button>
        </div>
      )}

      {/* Educational Info */}
      <div className="info-section stego-info">
        <h4>📚 How Steganography Works</h4>
        <ul>
          <li><strong>LSB Encoding:</strong> Modifies the least significant bits of color channels</li>
          <li><strong>Invisible to Eye:</strong> Changes are too small to see in the image</li>
          <li><strong>Capacity:</strong> Can hide ~1 byte per pixel (depends on image size)</li>
          <li><strong>Undetectable:</strong> Unlike encryption, steganography hides the fact data exists</li>
          <li><strong>Real-World Use:</strong> Watermarking, copyright protection, covert communication</li>
        </ul>
      </div>

      {/* Security Disclaimer */}
      <div className="disclaimer stego-disclaimer">
        ⚠️ <strong>Educational Purpose Only</strong><br/>
        This tool is for learning steganography concepts. Real steganography also uses encryption for security.
      </div>
    </div>
  );
}
