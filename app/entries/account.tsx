// The account page's entry (/conta, /en/account, /plus/link).
import "@/app/globals.css";
import "./fonts.css";
import { createRoot } from "react-dom/client";
import { AccountPage } from "@/selfhost/AccountPage";

const lang = document.documentElement.lang === "en" ? "en" : "pt";
createRoot(document.getElementById("main")!).render(<AccountPage lang={lang} />);
