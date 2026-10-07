// The phone app's entry (/app/ and /en/app/): the shared PhoneApp, as miblo.ai serves it.
import "@/app/globals.css";
import "./fonts.css";
import { createRoot } from "react-dom/client";
import { PhoneApp } from "@/components/phone/PhoneApp";

const lang = document.documentElement.lang === "en" ? "en" : "pt";
createRoot(document.getElementById("main")!).render(<PhoneApp lang={lang} />);
