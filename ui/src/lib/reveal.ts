/** Scroll-entry reveal: adds .reveal, then .revealed once when the element
 * enters the viewport. IntersectionObserver only; no scroll listeners. */
export function reveal(node: HTMLElement, opts: { delay?: number } = {}) {
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
