export function reveal(node: HTMLElement, opts: { delay?: number } = {}) {
  if (typeof IntersectionObserver === "undefined") return;
  node.classList.add("reveal");
  if (opts.delay) node.style.transitionDelay = `${opts.delay}ms`;
  const io = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          node.classList.add("revealed");
          io.disconnect();
          break;
        }
      }
    },
    { threshold: 0.06 },
  );
  io.observe(node);
  return {
    destroy() {
      io.disconnect();
    },
  };
}
