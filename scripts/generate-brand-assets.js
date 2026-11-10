/**
 * ScamLens Branding & Android Resource Generator
 * Uses the exact provided ScamLens logo image (app/www/assets/scamlens-logo-source.jpg)
 * to generate:
 * 1. Header & Web Logo PNGs (app/www/assets/logo.png, app/www/assets/favicon.png)
 * 2. Android Mipmap Launcher Icons (ic_launcher.png, ic_launcher_round.png, ic_launcher_foreground.png)
 *    across mdpi, hdpi, xhdpi, xxhdpi, xxxhdpi
 * 3. Android Launch Splash Screens (drawable/splash.png and drawable-{port,land}-{mdpi..xxxhdpi}/splash.png)
 */
const fs = require('fs');
const path = require('path');
const jpeg = require('jpeg-js');
const { PNG } = require('pngjs');

const ROOT_DIR = path.resolve(__dirname, '..');
const SOURCE_JPG = path.join(ROOT_DIR, 'app', 'www', 'assets', 'scamlens-logo-source.jpg');
const ANDROID_RES_DIR = path.join(ROOT_DIR, 'android', 'app', 'src', 'main', 'res');

if (!fs.existsSync(SOURCE_JPG)) {
  console.error('Source logo image not found at:', SOURCE_JPG);
  process.exit(1);
}

const rawJpg = jpeg.decode(fs.readFileSync(SOURCE_JPG), { useTArray: true });
const srcW = rawJpg.width;
const srcH = rawJpg.height;
const srcData = rawJpg.data;

console.log(`[BrandGen] Loaded source logo: ${srcW}x${srcH}`);

// Sample the exact deep teal background color from inside the badge (e.g., at x=512, y=130)
const sampleIdx = (130 * srcW + 512) * 4;
const bgTeal = {
  r: srcData[sampleIdx],
  g: srcData[sampleIdx + 1],
  b: srcData[sampleIdx + 2]
};
const bgTealHex = '#' + [bgTeal.r, bgTeal.g, bgTeal.b].map(v => v.toString(16).padStart(2, '0')).join('').toUpperCase();
console.log(`[BrandGen] Sampled badge deep teal: RGB(${bgTeal.r}, ${bgTeal.g}, ${bgTeal.b}) = ${bgTealHex}`);

// Flood-fill from the 4 corners to identify the outer white background outside the rounded-square badge
const isOuterBg = new Uint8Array(srcW * srcH);
const queue = [];

function pushCorner(x, y) {
  const idx = y * srcW + x;
  if (!isOuterBg[idx]) {
    isOuterBg[idx] = 1;
    queue.push(idx);
  }
}

pushCorner(0, 0);
pushCorner(srcW - 1, 0);
pushCorner(0, srcH - 1);
pushCorner(srcW - 1, srcH - 1);

let head = 0;
while (head < queue.length) {
  const curr = queue[head++];
  const cx = curr % srcW;
  const cy = (curr - cx) / srcW;

  const neighbors = [
    [cx - 1, cy],
    [cx + 1, cy],
    [cx, cy - 1],
    [cx, cy + 1]
  ];

  for (let i = 0; i < neighbors.length; i++) {
    const nx = neighbors[i][0];
    const ny = neighbors[i][1];
    if (nx < 0 || nx >= srcW || ny < 0 || ny >= srcH) continue;
    const nIdx = ny * srcW + nx;
    if (isOuterBg[nIdx]) continue;

    const pIdx = nIdx * 4;
    const r = srcData[pIdx];
    const g = srcData[pIdx + 1];
    const b = srcData[pIdx + 2];
    // Outer background is white/light gray transition around the dark teal badge
    if (r > 180 && g > 195 && b > 195) {
      isOuterBg[nIdx] = 1;
      queue.push(nIdx);
    }
  }
}

// Create a clean RGBA buffer of the source image:
// - Outer background pixels become transparent (with smooth anti-aliased edge)
// - Badge and inner artwork remain 100% untouched
const badgeRgba = new Uint8Array(srcW * srcH * 4);
// Also create an "unbounded teal canvas" version where outer background pixels are filled with bgTeal
// so adaptive icons & round icons have zero white border when scaled or masked!
const symbolOnTealRgba = new Uint8Array(srcW * srcH * 4);

for (let y = 0; y < srcH; y++) {
  for (let x = 0; x < srcW; x++) {
    const idx = y * srcW + x;
    const pIdx = idx * 4;
    const r = srcData[pIdx];
    const g = srcData[pIdx + 1];
    const b = srcData[pIdx + 2];

    if (isOuterBg[idx]) {
      badgeRgba[pIdx] = r;
      badgeRgba[pIdx + 1] = g;
      badgeRgba[pIdx + 2] = b;
      badgeRgba[pIdx + 3] = 0;

      symbolOnTealRgba[pIdx] = bgTeal.r;
      symbolOnTealRgba[pIdx + 1] = bgTeal.g;
      symbolOnTealRgba[pIdx + 2] = bgTeal.b;
      symbolOnTealRgba[pIdx + 3] = 255;
    } else {
      // Check if adjacent to outerBg for smooth edge anti-aliasing
      let nearOuter = false;
      if (x > 0 && isOuterBg[idx - 1]) nearOuter = true;
      if (x < srcW - 1 && isOuterBg[idx + 1]) nearOuter = true;
      if (y > 0 && isOuterBg[idx - srcW]) nearOuter = true;
      if (y < srcH - 1 && isOuterBg[idx + srcW]) nearOuter = true;

      if (nearOuter && r > 60) {
        // Blend transition pixel along the outer boundary toward bgTeal
        const lum = (r + g + b) / (3 * 255);
        const alpha = Math.max(0, Math.min(255, Math.round((1 - lum) * 255)));
        badgeRgba[pIdx] = bgTeal.r;
        badgeRgba[pIdx + 1] = bgTeal.g;
        badgeRgba[pIdx + 2] = bgTeal.b;
        badgeRgba[pIdx + 3] = alpha;
      } else {
        badgeRgba[pIdx] = r;
        badgeRgba[pIdx + 1] = g;
        badgeRgba[pIdx + 2] = b;
        badgeRgba[pIdx + 3] = 255;
      }

      // For symbolOnTealRgba (adaptive & round icons), only keep inner symbol strokes (x in 105..865, y in 180..820)
      // and fill all outer badge border pixels uniformly with bgTeal so there is zero seam/outline
      const inSymbolBox = (x >= 105 && x <= 865 && y >= 180 && y <= 820);
      if (inSymbolBox && g > 85) {
        symbolOnTealRgba[pIdx] = r;
        symbolOnTealRgba[pIdx + 1] = g;
        symbolOnTealRgba[pIdx + 2] = b;
        symbolOnTealRgba[pIdx + 3] = 255;
      } else {
        symbolOnTealRgba[pIdx] = bgTeal.r;
        symbolOnTealRgba[pIdx + 1] = bgTeal.g;
        symbolOnTealRgba[pIdx + 2] = bgTeal.b;
        symbolOnTealRgba[pIdx + 3] = 255;
      }
    }
  }
}

/**
 * High-quality area-averaging downsampler from a cropped region of a source RGBA buffer
 */
function renderCroppedResized(srcBuf, cropX, cropY, cropW, cropH, outW, outH) {
  const png = new PNG({ width: outW, height: outH });
  const scaleX = cropW / outW;
  const scaleY = cropH / outH;

  for (let oy = 0; oy < outH; oy++) {
    const sy0 = cropY + oy * scaleY;
    const sy1 = sy0 + scaleY;
    const iy0 = Math.max(0, Math.floor(sy0));
    const iy1 = Math.min(srcH - 1, Math.ceil(sy1));

    for (let ox = 0; ox < outW; ox++) {
      const sx0 = cropX + ox * scaleX;
      const sx1 = sx0 + scaleX;
      const ix0 = Math.max(0, Math.floor(sx0));
      const ix1 = Math.min(srcW - 1, Math.ceil(sx1));

      let sumR = 0, sumG = 0, sumB = 0, sumA = 0, weightSum = 0;
      for (let sy = iy0; sy <= iy1; sy++) {
        const wy = Math.min(sy + 1, sy1) - Math.max(sy, sy0);
        if (wy <= 0) continue;
        for (let sx = ix0; sx <= ix1; sx++) {
          const wx = Math.min(sx + 1, sx1) - Math.max(sx, sx0);
          if (wx <= 0) continue;
          const w = wx * wy;
          const pIdx = (sy * srcW + sx) * 4;
          const a = srcBuf[pIdx + 3] / 255;
          sumR += srcBuf[pIdx] * a * w;
          sumG += srcBuf[pIdx + 1] * a * w;
          sumB += srcBuf[pIdx + 2] * a * w;
          sumA += a * w;
          weightSum += w;
        }
      }

      const outIdx = (oy * outW + ox) * 4;
      if (weightSum > 0 && sumA > 0) {
        png.data[outIdx] = Math.round(sumR / sumA);
        png.data[outIdx + 1] = Math.round(sumG / sumA);
        png.data[outIdx + 2] = Math.round(sumB / sumA);
        png.data[outIdx + 3] = Math.round((sumA / weightSum) * 255);
      } else {
        png.data[outIdx] = 0;
        png.data[outIdx + 1] = 0;
        png.data[outIdx + 2] = 0;
        png.data[outIdx + 3] = 0;
      }
    }
  }
  return png;
}

function savePng(png, destPath) {
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  fs.writeFileSync(destPath, PNG.sync.write(png));
}

// 1. Generate Web & Mobile App Header Logos (tight crop around the rounded-square badge: 44..980)
const BADGE_CROP = { x: 44, y: 48, w: 932, h: 928 };
const headerLogo256 = renderCroppedResized(badgeRgba, BADGE_CROP.x, BADGE_CROP.y, BADGE_CROP.w, BADGE_CROP.h, 256, 256);
savePng(headerLogo256, path.join(ROOT_DIR, 'app', 'www', 'assets', 'logo.png'));

const favicon64 = renderCroppedResized(badgeRgba, BADGE_CROP.x, BADGE_CROP.y, BADGE_CROP.w, BADGE_CROP.h, 64, 64);
savePng(favicon64, path.join(ROOT_DIR, 'app', 'www', 'assets', 'favicon.png'));
console.log('[BrandGen] Generated app/www/assets/logo.png (256x256) and favicon.png (64x64)');

// 2. Generate Android Mipmap Launcher Icons across all 5 densities
const MIPMAP_SPECS = [
  { folder: 'mipmap-mdpi', legacySize: 48, adaptiveSize: 108 },
  { folder: 'mipmap-hdpi', legacySize: 72, adaptiveSize: 162 },
  { folder: 'mipmap-xhdpi', legacySize: 96, adaptiveSize: 216 },
  { folder: 'mipmap-xxhdpi', legacySize: 144, adaptiveSize: 324 },
  { folder: 'mipmap-xxxhdpi', legacySize: 192, adaptiveSize: 432 }
];

for (const spec of MIPMAP_SPECS) {
  const dir = path.join(ANDROID_RES_DIR, spec.folder);

  // A) ic_launcher.png (legacy rounded-square icon with tight badge crop)
  const legacyPng = renderCroppedResized(
    badgeRgba,
    BADGE_CROP.x,
    BADGE_CROP.y,
    BADGE_CROP.w,
    BADGE_CROP.h,
    spec.legacySize,
    spec.legacySize
  );
  savePng(legacyPng, path.join(dir, 'ic_launcher.png'));

  // B) ic_launcher_round.png (circular masked icon with full artwork inside circle)
  // Using a 1080x1080 virtual window centered on the symbol so the shield + lens fit cleanly inside the circle
  const roundPng = renderCroppedResized(
    symbolOnTealRgba,
    -28,
    -28,
    1080,
    1080,
    spec.legacySize,
    spec.legacySize
  );
  const rCenter = (spec.legacySize - 1) / 2;
  const maxRadius = spec.legacySize / 2 - 0.5;
  for (let y = 0; y < spec.legacySize; y++) {
    for (let x = 0; x < spec.legacySize; x++) {
      const dist = Math.hypot(x - rCenter, y - rCenter);
      const pIdx = (y * spec.legacySize + x) * 4;
      if (dist > maxRadius + 0.7) {
        roundPng.data[pIdx + 3] = 0;
      } else if (dist > maxRadius - 0.7) {
        const frac = (maxRadius + 0.7 - dist) / 1.4;
        roundPng.data[pIdx + 3] = Math.round(roundPng.data[pIdx + 3] * Math.max(0, Math.min(1, frac)));
      }
    }
  }
  savePng(roundPng, path.join(dir, 'ic_launcher_round.png'));

  // C) ic_launcher_foreground.png (Adaptive Icon 108dp canvas: inner 66dp is the safe zone)
  // The inner artwork in the 1024x1024 source spans ~740px.
  // Mapping a 1260x1260 window centered on (512, 512) onto the 108dp canvas puts the 740px symbol
  // at 740/1260 = 58.7% of 108dp (~63.4dp), right inside the 66dp safe zone!
  const fgPng = new PNG({ width: spec.adaptiveSize, height: spec.adaptiveSize });
  // Fill entire adaptive canvas with bgTeal first
  for (let i = 0; i < fgPng.data.length; i += 4) {
    fgPng.data[i] = bgTeal.r;
    fgPng.data[i + 1] = bgTeal.g;
    fgPng.data[i + 2] = bgTeal.b;
    fgPng.data[i + 3] = 255;
  }
  // Render the 1024x1024 symbolOnTeal centered into the middle 81% of the adaptive canvas
  const insetSize = Math.round(spec.adaptiveSize * 0.78);
  const insetOffset = Math.round((spec.adaptiveSize - insetSize) / 2);
  const symbolScaled = renderCroppedResized(symbolOnTealRgba, 60, 60, 904, 904, insetSize, insetSize);
  for (let y = 0; y < insetSize; y++) {
    for (let x = 0; x < insetSize; x++) {
      const srcIdx = (y * insetSize + x) * 4;
      const dstIdx = ((y + insetOffset) * spec.adaptiveSize + (x + insetOffset)) * 4;
      fgPng.data[dstIdx] = symbolScaled.data[srcIdx];
      fgPng.data[dstIdx + 1] = symbolScaled.data[srcIdx + 1];
      fgPng.data[dstIdx + 2] = symbolScaled.data[srcIdx + 2];
      fgPng.data[dstIdx + 3] = 255;
    }
  }
  savePng(fgPng, path.join(dir, 'ic_launcher_foreground.png'));
}
console.log('[BrandGen] Generated all Android mipmap icons (mdpi, hdpi, xhdpi, xxhdpi, xxxhdpi)');

// 3. Generate Splash Screens across all drawable folders
// Using clean white (#FFFFFF) background with the centered ScamLens rounded-square badge
const SPLASH_SPECS = [
  { file: 'drawable/splash.png', w: 480, h: 800, logoSize: 180 },
  { file: 'drawable-port-mdpi/splash.png', w: 320, h: 480, logoSize: 120 },
  { file: 'drawable-port-hdpi/splash.png', w: 480, h: 800, logoSize: 180 },
  { file: 'drawable-port-xhdpi/splash.png', w: 720, h: 1280, logoSize: 260 },
  { file: 'drawable-port-xxhdpi/splash.png', w: 960, h: 1600, logoSize: 340 },
  { file: 'drawable-port-xxxhdpi/splash.png', w: 1280, h: 1920, logoSize: 440 },
  { file: 'drawable-land-mdpi/splash.png', w: 480, h: 320, logoSize: 120 },
  { file: 'drawable-land-hdpi/splash.png', w: 800, h: 480, logoSize: 180 },
  { file: 'drawable-land-xhdpi/splash.png', w: 1280, h: 720, logoSize: 240 },
  { file: 'drawable-land-xxhdpi/splash.png', w: 1600, h: 960, logoSize: 320 },
  { file: 'drawable-land-xxxhdpi/splash.png', w: 1920, h: 1280, logoSize: 400 }
];

for (const sp of SPLASH_SPECS) {
  const splashPng = new PNG({ width: sp.w, height: sp.h });
  // Fill with clean white (#FFFFFF) matching the outer background of the source logo
  for (let i = 0; i < splashPng.data.length; i += 4) {
    splashPng.data[i] = 255;
    splashPng.data[i + 1] = 255;
    splashPng.data[i + 2] = 255;
    splashPng.data[i + 3] = 255;
  }

  const logoPatch = renderCroppedResized(
    badgeRgba,
    BADGE_CROP.x,
    BADGE_CROP.y,
    BADGE_CROP.w,
    BADGE_CROP.h,
    sp.logoSize,
    sp.logoSize
  );
  const startX = Math.round((sp.w - sp.logoSize) / 2);
  const startY = Math.round((sp.h - sp.logoSize) / 2);

  for (let y = 0; y < sp.logoSize; y++) {
    for (let x = 0; x < sp.logoSize; x++) {
      const sIdx = (y * sp.logoSize + x) * 4;
      const a = logoPatch.data[sIdx + 3] / 255;
      if (a <= 0) continue;
      const dIdx = ((startY + y) * sp.w + (startX + x)) * 4;
      splashPng.data[dIdx] = Math.round(logoPatch.data[sIdx] * a + 255 * (1 - a));
      splashPng.data[dIdx + 1] = Math.round(logoPatch.data[sIdx + 1] * a + 255 * (1 - a));
      splashPng.data[dIdx + 2] = Math.round(logoPatch.data[sIdx + 2] * a + 255 * (1 - a));
      splashPng.data[dIdx + 3] = 255;
    }
  }

  savePng(splashPng, path.join(ANDROID_RES_DIR, sp.file));
}
console.log('[BrandGen] Generated all 11 Android splash screen drawables.');
