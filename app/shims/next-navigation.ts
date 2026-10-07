// The two Next.js navigation hooks the shared code uses, for the plain (Vite) build: the phone
// app and the account page are single documents, so navigation is the browser's own.
export function usePathname(): string {
  return typeof location === "undefined" ? "/" : location.pathname;
}

export function useRouter() {
  return {
    push: (href: string) => location.assign(href),
    replace: (href: string) => location.replace(href),
    refresh: () => {},
    back: () => history.back(),
  };
}
