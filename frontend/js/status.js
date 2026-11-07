/* Neora - language + live status labels.
   detectRaw(text) finds the language of the user's OWN words (before anything is sent), detect(text) is the same
   but always returns a UI language, text(lang, status) gives the localized live status, t(lang, key) gives UI strings. */
(function(){
var D={
 en:{think:'Thinking',search:'Searching the web',read:'Reading a page',run:'Running a command',report:'Writing the report',inspect:'Inspecting in a sandbox',answer:'Writing the answer'},
 tr:{think:'Düşünüyor',search:'İnternette aranıyor',read:'Sayfa okunuyor',run:'Komut çalıştırılıyor',report:'Rapor yazılıyor',inspect:'Sandbox\u2019ta inceleniyor',answer:'Cevap yazılıyor'},
 es:{think:'Pensando',search:'Buscando en la web',read:'Leyendo una página',run:'Ejecutando un comando',report:'Escribiendo el informe',inspect:'Analizando en un sandbox',answer:'Escribiendo la respuesta'},
 fr:{think:'Réflexion',search:'Recherche sur le web',read:'Lecture d\u2019une page',run:'Exécution d\u2019une commande',report:'Rédaction du rapport',inspect:'Analyse dans un sandbox',answer:'Rédaction de la réponse'},
 de:{think:'Denke nach',search:'Suche im Web',read:'Lese eine Seite',run:'Führe einen Befehl aus',report:'Schreibe den Bericht',inspect:'Prüfe in einer Sandbox',answer:'Schreibe die Antwort'},
 pt:{think:'Pensando',search:'Pesquisando na web',read:'Lendo uma página',run:'Executando um comando',report:'Escrevendo o relatório',inspect:'Analisando em um sandbox',answer:'Escrevendo a resposta'},
 it:{think:'Sto pensando',search:'Cerco sul web',read:'Leggo una pagina',run:'Eseguo un comando',report:'Scrivo il report',inspect:'Analizzo in una sandbox',answer:'Scrivo la risposta'},
 ru:{think:'Думаю',search:'Ищу в интернете',read:'Читаю страницу',run:'Выполняю команду',report:'Пишу отчёт',inspect:'Проверяю в песочнице',answer:'Пишу ответ'},
 ar:{think:'يفكّر',search:'يبحث في الويب',read:'يقرأ صفحة',run:'ينفّذ أمرًا',report:'يكتب التقرير',inspect:'يفحص في بيئة معزولة',answer:'يكتب الإجابة'},
 zh:{think:'思考中',search:'正在搜索网页',read:'正在读取页面',run:'正在运行命令',report:'正在撰写报告',inspect:'正在沙箱中检查',answer:'正在撰写回答'},
 ja:{think:'考え中',search:'ウェブを検索中',read:'ページを読み込み中',run:'コマンドを実行中',report:'レポートを作成中',inspect:'サンドボックスで検査中',answer:'回答を作成中'}
};
/* UI strings. Order of keys = order of each array. Missing translations fall back to English. */
var K=['tlh','dl','search','read','cmd','tool','sbx','blocked','nonet','ro','cleanup','receipt','signed','fetcher','ok','bad','tail','crit','high','med','low','errT','retry','emptyT','emptyB','noreachT','noreachB','timeout','busy','rate','srv','by','queued'];
var U={
 en:['Tools & output','Download report','Search','Read page','Sandbox','Tool','Isolated sandbox','BLOCKED by policy','no network','read-only','cleanup','receipt','signed','Isolated fetcher \u00B7 SSRF-guarded \u00B7 no host access','fetch & detonation containers destroyed','fetch & detonation containers cleanup failed','detonation: no network, read-only','critical','high','medium','low','Something went wrong','Please try again.','No answer','The agent returned an empty response.','Couldn\u2019t reach the agent','Check the connection and try again.','The request timed out.','The server is busy right now. Try again in a few seconds.','Too many requests. Try again in a minute.','Server error','Answered by','Queued: Neora will answer next'],
 tr:['Araçlar ve çıktı','Raporu indir','Arama','Sayfa oku','Sandbox','Araç','İzole sandbox','Politika tarafından ENGELLENDİ','ağ yok','salt okunur','temizlik','makbuz','imzalı','İzole getirici \u00B7 SSRF korumalı \u00B7 ana sisteme erişim yok','indirme ve çalıştırma konteynerleri yok edildi','indirme ve çalıştırma konteynerleri temizlenemedi','çalıştırma: ağ yok, salt okunur','kritik','yüksek','orta','düşük','Bir şeyler ters gitti','Lütfen tekrar dene.','Cevap yok','Ajan boş bir cevap döndürdü.','Ajana ulaşılamadı','Bağlantını kontrol edip tekrar dene.','İstek zaman aşımına uğradı.','Sunucu şu an meşgul. Birkaç saniye sonra tekrar dene.','Çok fazla istek. Bir dakika sonra tekrar dene.','Sunucu hatası','Cevaplayan model','Sıraya alındı: Neora sıradaki cevabı verecek'],
 es:['Herramientas y resultado','Descargar informe','Búsqueda','Leer página','Sandbox','Herramienta','Sandbox aislado','BLOQUEADO por la política','sin red','solo lectura','limpieza','recibo','firmado','Lector aislado \u00B7 protegido contra SSRF \u00B7 sin acceso al host','contenedores de descarga y ejecución destruidos','falló la limpieza de los contenedores de descarga y ejecución','ejecución: sin red, solo lectura','crítico','alto','medio','bajo','Algo salió mal','Inténtalo de nuevo.','Sin respuesta','El agente devolvió una respuesta vacía.','No se pudo contactar con el agente','Comprueba la conexión e inténtalo de nuevo.','La solicitud agotó el tiempo de espera.','El servidor está ocupado. Inténtalo de nuevo en unos segundos.','Demasiadas solicitudes. Inténtalo de nuevo en un minuto.','Error del servidor','Respondido por','En cola: Neora responderá a continuación'],
 fr:['Outils et résultat','Télécharger le rapport','Recherche','Lire la page','Sandbox','Outil','Sandbox isolé','BLOQUÉ par la politique','pas de réseau','lecture seule','nettoyage','reçu','signé','Récupérateur isolé \u00B7 protégé contre SSRF \u00B7 aucun accès à l\u2019hôte','conteneurs de téléchargement et d\u2019exécution détruits','échec du nettoyage des conteneurs de téléchargement et d\u2019exécution','exécution : pas de réseau, lecture seule','critique','élevé','moyen','faible','Un problème est survenu','Veuillez réessayer.','Aucune réponse','L\u2019agent a renvoyé une réponse vide.','Impossible de joindre l\u2019agent','Vérifiez la connexion et réessayez.','La requête a expiré.','Le serveur est occupé. Réessayez dans quelques secondes.','Trop de requêtes. Réessayez dans une minute.','Erreur du serveur','Réponse de','En file d\u2019attente : Neora répondra ensuite'],
 de:['Tools und Ausgabe','Bericht herunterladen','Suche','Seite lesen','Sandbox','Tool','Isolierte Sandbox','Durch Richtlinie BLOCKIERT','kein Netzwerk','schreibgeschützt','Bereinigung','Beleg','signiert','Isolierter Abruf \u00B7 SSRF-geschützt \u00B7 kein Host-Zugriff','Download- und Ausführungs-Container zerstört','Bereinigung der Download- und Ausführungs-Container fehlgeschlagen','Ausführung: kein Netzwerk, schreibgeschützt','kritisch','hoch','mittel','niedrig','Etwas ist schiefgelaufen','Bitte versuche es erneut.','Keine Antwort','Der Agent hat eine leere Antwort geliefert.','Agent nicht erreichbar','Prüfe die Verbindung und versuche es erneut.','Die Anfrage ist abgelaufen.','Der Server ist gerade ausgelastet. Versuche es in ein paar Sekunden erneut.','Zu viele Anfragen. Versuche es in einer Minute erneut.','Serverfehler','Beantwortet von','In der Warteschlange: Neora antwortet als Nächstes'],
 pt:['Ferramentas e saída','Baixar relatório','Pesquisa','Ler página','Sandbox','Ferramenta','Sandbox isolado','BLOQUEADO pela política','sem rede','somente leitura','limpeza','recibo','assinado','Leitor isolado \u00B7 protegido contra SSRF \u00B7 sem acesso ao host','contêineres de download e execução destruídos','falha na limpeza dos contêineres de download e execução','execução: sem rede, somente leitura','crítico','alto','médio','baixo','Algo deu errado','Tente novamente.','Sem resposta','O agente retornou uma resposta vazia.','Não foi possível alcançar o agente','Verifique a conexão e tente novamente.','A solicitação expirou.','O servidor está ocupado. Tente novamente em alguns segundos.','Muitas solicitações. Tente novamente em um minuto.','Erro do servidor','Respondido por','Na fila: Neora responderá em seguida'],
 it:['Strumenti e output','Scarica il report','Ricerca','Leggi pagina','Sandbox','Strumento','Sandbox isolata','BLOCCATO dalla policy','nessuna rete','sola lettura','pulizia','ricevuta','firmato','Fetcher isolato \u00B7 protetto da SSRF \u00B7 nessun accesso all\u2019host','container di download ed esecuzione distrutti','pulizia dei container di download ed esecuzione non riuscita','esecuzione: nessuna rete, sola lettura','critico','alto','medio','basso','Qualcosa è andato storto','Riprova.','Nessuna risposta','L\u2019agente ha restituito una risposta vuota.','Impossibile raggiungere l\u2019agente','Controlla la connessione e riprova.','La richiesta è scaduta.','Il server è occupato. Riprova tra qualche secondo.','Troppe richieste. Riprova tra un minuto.','Errore del server','Risposta di','In coda: Neora risponderà subito dopo'],
 ru:['Инструменты и вывод','Скачать отчёт','Поиск','Чтение страницы','Песочница','Инструмент','Изолированная песочница','ЗАБЛОКИРОВАНО политикой','без сети','только чтение','очистка','квитанция','подписано','Изолированная загрузка \u00B7 защита от SSRF \u00B7 без доступа к хосту','контейнеры загрузки и запуска уничтожены','не удалось очистить контейнеры загрузки и запуска','запуск: без сети, только чтение','критический','высокий','средний','низкий','Что-то пошло не так','Попробуйте ещё раз.','Нет ответа','Агент вернул пустой ответ.','Не удалось связаться с агентом','Проверьте соединение и попробуйте снова.','Время запроса истекло.','Сервер сейчас занят. Повторите через несколько секунд.','Слишком много запросов. Повторите через минуту.','Ошибка сервера','Ответила модель','В очереди: Neora ответит следующим'],
 ar:[],zh:[],ja:[]
};
var W={
 tr:/\b(bir|ve|bu|için|icin|mi|mı|mu|mü|bana|bunu|nedir|neden|nasıl|nasil|lütfen|lutfen|merhaba|selam|güvenli|guvenli|hazırla|hazirla|araştır|arastir|ara|bul|yaz|evet|hayır|hayir|tamam|ile|daha|çok|cok|ne|kim|nerede|ben|sen|var|yok|değil|degil|gibi|ama|olarak|nasılsın|nasilsin|teşekkürler|tesekkurler|sağol|sagol|analiz|paket|kontrol|et|eder|misin|musun|bakar|bakabilir|olur|olsun|mısın|naber|slm|mrb)\b/g,
 es:/\b(el|la|los|las|de|que|qué|para|por|como|cómo|hola|gracias|puedes|quiero|una|un|con|es|esto|favor|pero|muy|está|esta|mi)\b/g,
 fr:/\b(le|les|des|est|pour|une|que|bonjour|merci|peux|quelle|comment|je|vous|avec|dans|ce|pas|mais|très|sur|mon)\b/g,
 de:/\b(der|die|das|und|ist|nicht|ich|bitte|kannst|wie|was|für|eine|mit|ein|zu|auf|aber|sehr|mein|hallo|danke)\b/g,
 pt:/\b(você|voce|não|nao|uma|para|com|olá|ola|obrigado|como|que|pode|quero|isso|em|um|mas|muito|meu)\b/g,
 it:/\b(il|lo|che|di|per|non|sono|ciao|grazie|come|puoi|voglio|una|con|questo|è|ma|molto|mio|perché)\b/g,
 nl:/\b(het|een|niet|ik|jij|kunt|kun|hoe|alsjeblieft|hallo|dank|voor|met|naar|ook|maar|wat|mijn|zijn)\b/g,
 en:/\b(the|and|is|are|what|how|please|can|you|this|that|with|for|it|my|hello|hi|thanks|why|do|does|me|about)\b/g
};
/* Language of the user's own words. Ignores URLs, code and the [attached: ...] marker. Returns a code or 'auto' (not sure). */
function detectRaw(t){
 t=String(t||'').replace(/\[(?:attached|uploaded_file):[^\]]*\]/gi,' ').replace(/https?:\/\/\S+/gi,' ').replace(/```[\s\S]*?```/g,' ').slice(0,600);
 if(/[\uAC00-\uD7AF]/.test(t))return'ko';
 if(/[\u3040-\u30FF]/.test(t))return'ja';
 if(/[\u4E00-\u9FFF]/.test(t))return'zh';
 if(/[\u0400-\u04FF]/.test(t))return'ru';
 if(/[\u0600-\u06FF]/.test(t))return'ar';
 if(/[\u0900-\u097F]/.test(t))return'hi';
 if(/[ğışİ]/.test(t))return'tr';
 var l=t.toLowerCase(),sc=[],k;
 for(k in W)sc.push([k,(l.match(W[k])||[]).length]);
 sc.forEach(function(x){
  if(x[0]==='es'&&/[¿¡ñ]/.test(t))x[1]+=3;
  if(x[0]==='pt'&&/[ãõ]/.test(t))x[1]+=3;
  if(x[0]==='de'&&/[äß]/.test(t))x[1]+=2;
  if(x[0]==='fr'&&/[àâêèéùûœ]/.test(t))x[1]+=1});
 sc.sort(function(a,b){return b[1]-a[1]});
 if(!sc[0]||sc[0][1]<1||(sc[1]&&sc[1][1]===sc[0][1]))return'auto';
 return sc[0][0];
}
function detect(t){var c=detectRaw(t);return D[c]?c:'en'}
function text(lang,s){
 s=s||{};var d=D[lang]||D.en,label=d[s.k]||D.en[s.k]||d.think,x=String(s.d||'').slice(0,70),detail='';
 if(x){detail=s.k=='search'?'\u201C'+x+'\u201D':s.k=='run'?'$ '+x:(s.k=='read'||s.k=='inspect')?x:''}
 return{label:label,detail:detail};
}
function t(lang,key){var i=K.indexOf(key),a=U[lang];return(a&&a[i])||U.en[i]||key}
window.NEORA_STATUS={detect:detect,detectRaw:detectRaw,text:text,t:t};
})();
