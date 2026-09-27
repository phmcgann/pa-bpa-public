import clsx, { type ClassValue } from "clsx";

/** Join class names, dropping falsy ones. */
export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs);
}
