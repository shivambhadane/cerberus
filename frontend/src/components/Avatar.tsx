import { useEffect, useState } from "react";
import type { User } from "../types";

/** What to call someone: the name they signed up with, else the part of the address before the @. */
export function displayName(user: Pick<User, "name" | "email">): string {
  return user.name?.trim() || user.email.split("@")[0];
}

export function initialsOf(user: Pick<User, "name" | "email">): string {
  const words = user.name?.trim().split(/\s+/).filter(Boolean) ?? [];
  const letters = words.length ? words.map((word) => word[0]).slice(0, 2).join("") : user.email.slice(0, 2);
  return letters.toUpperCase() || "CB";
}

/**
 * The person's picture, or their initials when there is none.
 *
 * The picture URL is whatever the sign-in provider put in its token (a Google photo), so it can be
 * missing, expired or blocked; a failed load falls back to initials instead of a broken image.
 * `referrerPolicy="no-referrer"` matters for Google's image host, which refuses some cross-site referrers.
 */
export function Avatar({
  user,
  size = "md",
  label,
}: {
  user: Pick<User, "name" | "email" | "picture_url">;
  size?: "sm" | "md" | "lg";
  /** Set when the picture is content on its own (the Profile page). Elsewhere the name sits beside it. */
  label?: string;
}) {
  const [failed, setFailed] = useState(false);
  const url = user.picture_url;
  useEffect(() => setFailed(false), [url]);

  const a11y = label ? { role: "img", "aria-label": label } : { "aria-hidden": true as const };
  return (
    <span className={`avatar avatar-${size}`} {...a11y}>
      {url && !failed ? (
        <img src={url} alt="" referrerPolicy="no-referrer" loading="lazy" onError={() => setFailed(true)} />
      ) : (
        initialsOf(user)
      )}
    </span>
  );
}
