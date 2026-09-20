/**
 * A small set of inline icons (24px grid, 1.75 stroke, `currentColor`). They are decorative:
 * every one is `aria-hidden`, and whatever it sits beside carries the accessible name.
 */
const PATHS = {
  shield: "M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6L12 3Z",
  domains: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3Z",
  overview: "M4 4h7v7H4V4Zm9 0h7v4h-7V4ZM4 13h7v7H4v-7Zm9-3h7v10h-7V10Z",
  findings: "M12 3.5 2.8 19.5h18.4L12 3.5ZM12 10v4.5M12 17.2v.05",
  assets: "M4 5h16v6H4V5Zm0 8h16v6H4v-6ZM7.5 8h.01M7.5 16h.01",
  evidence: "M7 3h7l4 4v14H7V3Zm7 0v4h4M10 12h5M10 16h5",
  scans: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-5a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm0-4 5-5",
  plus: "M12 5v14M5 12h14",
  signout: "M10 4H5v16h5M15 8l4 4-4 4M19 12H9",
  flame: "M12 3c1 3.5 5 5.5 5 10a5 5 0 0 1-10 0c0-2 1-3.2 2-4.2.3 1.2.9 2 1.7 2.3C10.3 8.5 10.8 5.5 12 3Z",
  check: "M5 12.5 10 17.5 19 7",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-13.5V12l3 2",
  user: "M12 12a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9ZM4 21c0-4.4 3.6-7 8-7s8 2.6 8 7",
  external: "M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5",
  plug: "M9 3v5M15 3v5M6 8h12v3a6 6 0 0 1-12 0V8ZM12 17v4",
  eye: "M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z",
  eyeOff: "M9.88 9.88a3 3 0 1 0 4.24 4.24m-7.07-7.07 14.14 14.14M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61",
  flask: "M10 2v4.5L4.2 18A2 2 0 0 0 6 21h12a2 2 0 0 0 1.8-3L14 6.5V2h-4ZM8.5 2h7M7 15h10",
  terminal: "M4 17l6-6-6-6M12 19h8",
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name }: { name: IconName }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      <path d={PATHS[name]} />
    </svg>
  );
}
