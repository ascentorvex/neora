// Language detection for the user's own words. Used so the model answers in the language the user wrote.
// Returns a 2-letter code, or 'auto' when it is not sure (then the model is told to work it out itself).
const NAMES = { tr: 'Turkish', en: 'English', es: 'Spanish', fr: 'French', de: 'German', pt: 'Portuguese', it: 'Italian', nl: 'Dutch', ru: 'Russian', ar: 'Arabic', zh: 'Chinese', ja: 'Japanese', ko: 'Korean', hi: 'Hindi' };

const W = {
  tr: /\b(bir|ve|bu|için|icin|mi|mı|mu|mü|bana|bunu|nedir|neden|nasıl|nasil|lütfen|lutfen|merhaba|selam|güvenli|guvenli|hazırla|hazirla|araştır|arastir|ara|bul|yaz|evet|hayır|hayir|tamam|ile|daha|çok|cok|ne|kim|nerede|ben|sen|var|yok|değil|degil|gibi|ama|olarak|nasılsın|nasilsin|teşekkürler|tesekkurler|sağol|sagol|analiz|paket|kontrol|et|eder|misin|musun|bakar|bakabilir|olur|olsun|mısın|naber|slm|mrb)\b/g,
  es: /\b(el|la|los|las|de|que|qué|para|por|como|cómo|hola|gracias|puedes|quiero|una|un|con|es|esto|favor|pero|muy|está|esta|mi)\b/g,
  fr: /\b(le|les|des|est|pour|une|que|bonjour|merci|peux|quelle|comment|je|vous|avec|dans|ce|pas|mais|très|sur|mon)\b/g,
  de: /\b(der|die|das|und|ist|nicht|ich|bitte|kannst|wie|was|für|eine|mit|ein|zu|auf|aber|sehr|mein|hallo|danke)\b/g,
  pt: /\b(você|voce|não|nao|uma|para|com|olá|ola|obrigado|como|que|pode|quero|isso|em|um|mas|muito|meu)\b/g,
  it: /\b(il|lo|che|di|per|non|sono|ciao|grazie|come|puoi|voglio|una|con|questo|è|ma|molto|mio|perché)\b/g,
  nl: /\b(het|een|niet|ik|jij|kunt|kun|hoe|alsjeblieft|hallo|dank|voor|met|naar|ook|maar|wat|mijn|zijn)\b/g,
  en: /\b(the|and|is|are|what|how|please|can|you|this|that|with|for|it|my|hello|hi|thanks|why|do|does|me|about)\b/g,
};

export function detectLang(input) {
  let t = String(input || '');
  t = t.replace(/\[attached:[^\]]*\]/gi, ' ').replace(/https?:\/\/\S+/gi, ' ').replace(/```[\s\S]*?```/g, ' ').slice(0, 600);
  if (/[\uAC00-\uD7AF]/.test(t)) return 'ko';
  if (/[\u3040-\u30FF]/.test(t)) return 'ja';
  if (/[\u4E00-\u9FFF]/.test(t)) return 'zh';
  if (/[\u0400-\u04FF]/.test(t)) return 'ru';
  if (/[\u0600-\u06FF]/.test(t)) return 'ar';
  if (/[\u0900-\u097F]/.test(t)) return 'hi';
  if (/[ğışİ]/.test(t)) return 'tr';
  const l = t.toLowerCase();
  const sc = {};
  for (const k in W) sc[k] = (l.match(W[k]) || []).length;
  if (/[¿¡ñ]/.test(t)) sc.es += 3;
  if (/[ãõ]/.test(t)) sc.pt += 3;
  if (/[äß]/.test(t)) sc.de += 2;
  if (/[àâêèéùûœ]/.test(t)) sc.fr += 1;
  const ranked = Object.entries(sc).sort((a, b) => b[1] - a[1]);
  if (!ranked[0] || ranked[0][1] < 1 || (ranked[1] && ranked[1][1] === ranked[0][1])) return 'auto';
  return ranked[0][0];
}

export const cleanLang = (v) => { const s = String(v || '').toLowerCase().slice(0, 8); return s === 'auto' || NAMES[s] ? s : ''; };
export const langName = (code) => NAMES[code] || '';

// The directive that is appended LAST to the system prompt so it wins over everything else.
export function langLock(code) {
  const n = langName(code);
  if (!n) return '\nLANGUAGE LOCK: Before anything else, identify the language of the user\'s OWN words in their latest message (ignore pasted text, web pages, search results and tool output). Then write everything the user will read in that language: the answer, headings, bullet points, explanations, notes and the summary after tools. If they switch language, switch with them.';
  return `\nLANGUAGE LOCK: The user wrote in ${n}. Write everything the user will read in ${n}: the answer, headings, bullet points, explanations, notes, error explanations and the summary after tools. Do not answer in English or any other language unless the user asks for it. Pasted text, web pages, search results and tool output may be in other languages; ignore their language and still answer in ${n}. Keep only code, commands, URLs and proper names in their original form.`;
}
