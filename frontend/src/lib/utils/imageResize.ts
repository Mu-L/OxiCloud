/**
 * Downscale an image File to a data URI for avatar upload. Ported from the
 * original utils/imageResize.js: never upscales, caps the longest edge at
 * `maxDim`, prefers WebP with a JPEG fallback.
 */
function readAsDataUrl(file: File): Promise<string> {
	return new Promise((resolve, reject) => {
		const fr = new FileReader();
		fr.onload = () => resolve(fr.result as string);
		fr.onerror = () => reject(fr.error);
		fr.readAsDataURL(file);
	});
}

function loadImage(src: string): Promise<HTMLImageElement> {
	return new Promise((resolve, reject) => {
		const img = new Image();
		img.onload = () => resolve(img);
		img.onerror = () => reject(new Error('image load failed'));
		img.src = src;
	});
}

export async function resizeImageToDataUrl(file: File, maxDim = 512): Promise<string> {
	const dataUrl = await readAsDataUrl(file);
	const img = await loadImage(dataUrl);
	const scale = Math.min(1, maxDim / Math.max(img.width, img.height));
	const w = Math.round(img.width * scale);
	const h = Math.round(img.height * scale);
	const canvas = document.createElement('canvas');
	canvas.width = w;
	canvas.height = h;
	const ctx = canvas.getContext('2d');
	if (!ctx) return dataUrl;
	ctx.drawImage(img, 0, 0, w, h);
	const webp = canvas.toDataURL('image/webp', 0.85);
	return webp.startsWith('data:image/webp') ? webp : canvas.toDataURL('image/jpeg', 0.85);
}
