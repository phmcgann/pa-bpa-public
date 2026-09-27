import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "../../lib/cn";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

const VARIANTS: Record<Variant, string> = {
  primary: "bg-accent text-white hover:bg-accent-hover border border-transparent shadow-card",
  secondary: "bg-surface text-fg border border-line-strong hover:bg-surface-2 shadow-card",
  ghost: "bg-transparent text-fg-2 border border-transparent hover:bg-surface-3 hover:text-fg",
  danger: "bg-transparent text-critical-fg border border-transparent hover:bg-surface-3",
};
const SIZES: Record<Size, string> = {
  sm: "h-7 text-[12px] gap-1.5 rounded-md",
  md: "h-8 text-[13px] gap-2 rounded-lg",
};
// Padding lives apart from SIZES so an icon-only button never carries two competing px-* classes.
const PAD: Record<Size, string> = { sm: "px-2.5", md: "px-3" };
const SQUARE: Record<Size, string> = { sm: "w-7", md: "w-8" };

export const Button = forwardRef<HTMLButtonElement, ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant; size?: Size; iconOnly?: boolean;
}>(function Button({ variant = "secondary", size = "md", iconOnly, className, type = "button", ...rest }, ref) {
  return (
    <button
      ref={ref}
      type={type}
      className={cn(
        "inline-flex items-center justify-center font-medium whitespace-nowrap select-none [&_svg]:shrink-0",
        "transition-colors duration-150 disabled:opacity-50 disabled:pointer-events-none",
        VARIANTS[variant], SIZES[size], iconOnly ? SQUARE[size] : PAD[size], className,
      )}
      {...rest}
    />
  );
});
