/* Neora - runs before first paint: enables entrance animations unless reduced motion is requested */
(function(){var d=document.documentElement;if(!matchMedia('(prefers-reduced-motion: reduce)').matches){d.classList.add('entrance','entrance-s2');setTimeout(function(){d.classList.remove('entrance')},3500)}})();
