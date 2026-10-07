// Sets data-theme before first paint: the saved choice, else the system preference (the same
// script miblo.ai inlines; a file here, so the pages need no inline script under the CSP).
(()=>{try{var t=localStorage.getItem("miblo-theme");if(t!=="light"&&t!=="dark"){t=matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"}document.documentElement.dataset.theme=t}catch(e){}})();
