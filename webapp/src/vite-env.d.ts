/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "1" builds the web vault without the account register view. */
  readonly VITE_SIGNUPS_DISABLED?: string;
}

declare module 'qrcode-generator' {
  interface QrCode {
    addData(data: string): void;
    make(): void;
    createSvgTag(options?: { scalable?: boolean; margin?: number }): string;
  }
  export default function qrcode(typeNumber: number, errorCorrectionLevel: 'L' | 'M' | 'Q' | 'H'): QrCode;
}

interface BarcodeDetectorResult {
  rawValue: string;
}

interface BarcodeDetector {
  detect(image: ImageBitmapSource): Promise<BarcodeDetectorResult[]>;
}

interface BarcodeDetectorConstructor {
  new (options?: { formats?: string[] }): BarcodeDetector;
}

interface Window {
  BarcodeDetector?: BarcodeDetectorConstructor;
}

declare const __NODEWARDEN_DEMO__: boolean;
