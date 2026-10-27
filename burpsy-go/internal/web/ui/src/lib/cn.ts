import { clsx, type ClassValue } from "clsx";

/** Join conditional class names. The stylesheet is bespoke semantic CSS, not utilities. */
export function cn(...inputs: ClassValue[]): string {
 return clsx(inputs);
}
