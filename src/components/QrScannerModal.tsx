import React, { useEffect, useRef, useState } from 'react';
import jsQR from 'jsqr';
import { QrCode, Camera, Upload, X, CheckCircle2, AlertTriangle, Sparkles } from 'lucide-react';

interface QrScannerModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDecodedUrl: (url: string) => void;
}

export const QrScannerModal: React.FC<QrScannerModalProps> = ({
  isOpen,
  onClose,
  onDecodedUrl,
}) => {
  const [mode, setMode] = useState<'upload' | 'camera'>('upload');
  const [error, setError] = useState<string | null>(null);
  const [decodedResult, setDecodedResult] = useState<string | null>(null);
  const [cameraActive, setCameraActive] = useState(false);

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    if (!isOpen) {
      stopCamera();
      setError(null);
      setDecodedResult(null);
      setMode('upload');
    }
    return () => {
      stopCamera();
    };
  }, [isOpen]);

  const stopCamera = () => {
    if (rafRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
    setCameraActive(false);
  };

  const startCamera = async () => {
    setError(null);
    setDecodedResult(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
      });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
        setCameraActive(true);
        scanVideoFrame();
      }
    } catch {
      setError(
        'Camera access was unavailable or declined. You can upload a screenshot or photo of the QR code below instead.'
      );
      setMode('upload');
    }
  };

  const scanVideoFrame = () => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas) return;

    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      canvas.width = video.videoWidth;
      canvas.height = video.videoHeight;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'dontInvert',
        });
        if (code && code.data) {
          stopCamera();
          setDecodedResult(code.data.trim());
          return;
        }
      }
    }
    rafRef.current = requestAnimationFrame(scanVideoFrame);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    setDecodedResult(null);

    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        const canvas = canvasRef.current;
        if (!canvas) return;
        const maxDim = 900;
        const scale = Math.min(1, maxDim / Math.max(img.width, img.height));
        canvas.width = Math.max(1, Math.floor(img.width * scale));
        canvas.height = Math.max(1, Math.floor(img.height * scale));
        const ctx = canvas.getContext('2d');
        if (!ctx) return;
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code && code.data) {
          setDecodedResult(code.data.trim());
        } else {
          setError(
            'No clear QR code pattern was detected in that image. Try cropping closer to the QR square or use the sample QR test below.'
          );
        }
      };
      img.onerror = () => {
        setError('Could not read the selected image file.');
      };
      img.src = reader.result as string;
    };
    reader.readAsDataURL(file);
  };

  /**
   * Simulates decoding a real QR code from a parcel locker/parking sticker lure
   * so visitors can test the QR workflow even without a QR image on their device.
   */
  const handleSimulateSampleQr = () => {
    stopCamera();
    setError(null);
    setDecodedResult('https://dhl-parcel-redelivery-fee.example/qr-claim?scan_id=99412');
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-[90] flex items-center justify-center p-3 sm:p-4 bg-black/80 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="qr-modal-title"
    >
      <div className="w-full max-w-lg max-h-[90dvh] overflow-y-auto rounded-lg bg-[#2A1A14] border-2 border-[#C9A04A] text-[#F2E6C9] shadow-2xl">
        {/* Header */}
        <div className="px-4 sm:px-5 py-3.5 sm:py-4 bg-[#170E0B] border-b border-[#4A3024] flex items-center justify-between gap-2 sticky top-0 z-10">
          <div className="flex items-center gap-2.5">
            <QrCode className="w-5 h-5 text-[#C9A04A] shrink-0" />
            <h2 id="qr-modal-title" className="font-serif-display text-lg sm:text-xl font-bold text-[#F5CE7A]">
              Inspect a QR Code Link ("Quishing" Guard)
            </h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close QR scanner modal"
            className="min-w-[44px] min-h-[44px] shrink-0 rounded border border-[#4A3024] bg-[#2A1A14] text-[#F2E6C9] flex items-center justify-center hover:border-[#C9A04A] cursor-pointer"
          >
            <X className="w-5 h-5 text-[#C9A04A]" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4">
          <p className="text-sm text-[#D9C79F]">
            QR codes on parking meters, parcel slips, or emails often hide shortened or lookalike URLs. SHERLOCK decodes the QR image right in your browser so you can inspect the address before opening it.
          </p>

          {/* Mode Tabs */}
          <div className="grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => {
                stopCamera();
                setMode('upload');
              }}
              className={`min-h-[44px] px-3 py-2 rounded border text-sm font-medium flex items-center justify-center gap-2 transition-colors ${
                mode === 'upload'
                  ? 'bg-[#5A1F26] border-[#C9A04A] text-[#F5CE7A]'
                  : 'bg-[#170E0B] border-[#4A3024] text-[#D9C79F] hover:text-[#F2E6C9]'
              }`}
            >
              <Upload className="w-4 h-4" />
              <span>Upload QR Image</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('camera');
                startCamera();
              }}
              className={`min-h-[44px] px-3 py-2 rounded border text-sm font-medium flex items-center justify-center gap-2 transition-colors ${
                mode === 'camera'
                  ? 'bg-[#5A1F26] border-[#C9A04A] text-[#F5CE7A]'
                  : 'bg-[#170E0B] border-[#4A3024] text-[#D9C79F] hover:text-[#F2E6C9]'
              }`}
            >
              <Camera className="w-4 h-4" />
              <span>Use Camera</span>
            </button>
          </div>

          <canvas ref={canvasRef} className="hidden" />

          {mode === 'upload' && (
            <div className="border-2 border-dashed border-[#C9A04A]/60 rounded-md p-5 bg-[#170E0B]/70 text-center space-y-3">
              <Upload className="w-8 h-8 text-[#C9A04A] mx-auto" />
              <div>
                <label
                  htmlFor="qr-file-upload"
                  className="inline-flex min-h-[44px] items-center justify-center px-4 py-2 rounded brass-button font-semibold text-sm cursor-pointer"
                >
                  Choose QR Screenshot or Photo
                </label>
                <input
                  id="qr-file-upload"
                  type="file"
                  accept="image/*"
                  onChange={handleFileChange}
                  className="sr-only"
                />
              </div>
              <p className="text-xs text-[#D9C79F]">
                Decoded locally in your browser using HTML5 Canvas — your photo is never uploaded.
              </p>
            </div>
          )}

          {mode === 'camera' && (
            <div className="rounded-md overflow-hidden border border-[#C9A04A] bg-black relative aspect-video flex items-center justify-center">
              <video
                ref={videoRef}
                playsInline
                muted
                className="w-full h-full object-cover"
              />
              {!cameraActive && !error && (
                <p className="text-sm text-[#D9C79F] absolute">Starting camera lens…</p>
              )}
              <div className="pointer-events-none absolute inset-6 border-2 border-[#F5CE7A]/70 rounded" />
            </div>
          )}

          {/* Sample QR Quick Demo */}
          <div className="pt-1 flex items-center justify-between gap-2 border-t border-[#4A3024]">
            <span className="text-xs text-[#D9C79F]">Don’t have a QR code image handy?</span>
            <button
              type="button"
              onClick={handleSimulateSampleQr}
              className="min-h-[40px] px-3 py-1.5 rounded border border-[#C9A04A]/70 bg-[#170E0B] text-xs font-medium text-[#F5CE7A] hover:bg-[#5A1F26] flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-[#C9A04A]" />
              <span>Load sample parcel QR lure</span>
            </button>
          </div>

          {error && (
            <div className="p-3.5 rounded bg-[#B3342F]/20 border border-[#B3342F] text-sm text-[#F2E6C9] flex items-start gap-2.5">
              <AlertTriangle className="w-5 h-5 text-[#E9A872] shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {decodedResult && (
            <div className="p-4 rounded parchment-card space-y-3">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[#5A1F26]">
                <CheckCircle2 className="w-4 h-4 text-[#5E8B5A]" />
                <span>QR Destination Extracted (Not Opened)</span>
              </div>
              <p className="font-mono-code text-sm break-all bg-[#170E0B]/10 p-2.5 rounded border border-[#4A3024]/30 text-[#1B1410]">
                {decodedResult}
              </p>
              <div className="flex flex-col sm:flex-row gap-2">
                <button
                  type="button"
                  onClick={() => {
                    onDecodedUrl(decodedResult);
                    onClose();
                  }}
                  className="min-h-[44px] flex-1 px-4 py-2 rounded brass-button font-semibold text-sm flex items-center justify-center gap-2 cursor-pointer"
                >
                  <span>Investigate this QR Link</span>
                </button>
                <button
                  type="button"
                  onClick={() => setDecodedResult(null)}
                  className="min-h-[44px] px-4 py-2 rounded border border-[#4A3024] bg-[#2A1A14] text-[#F2E6C9] text-sm font-medium cursor-pointer"
                >
                  Scan Another
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
