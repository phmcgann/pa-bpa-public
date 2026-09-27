import { LayoutList, Monitor, Moon, Settings, Sun, Upload } from "lucide-react";
import { useEffect, useState, type ComponentType } from "react";
import { NavLink, Route, Routes, useLocation, useSearchParams } from "react-router-dom";
import { api } from "./api";
import { brand, Logo } from "@brand";
import { cn } from "./lib/cn";
import { ComparePage } from "./pages/ComparePage";
import { DashboardPage } from "./pages/DashboardPage";
import { HistoryPage } from "./pages/HistoryPage";
import { SettingsPage } from "./pages/SettingsPage";
import { UploadPage } from "./pages/UploadPage";
import { useTheme, type ThemePref } from "./theme";
import type { ClientSummary } from "./types";

const NAV: { to: string; label: string; icon: ComponentType<{ size?: number }>; end?: boolean }[] = [
  { to: "/", label: "Assessments", icon: LayoutList, end: true },
  { to: "/upload", label: "New assessment", icon: Upload },
  { to: "/settings", label: "Settings", icon: Settings },
];

function navClass({ isActive }: { isActive: boolean }) {
  return cn(
    "flex items-center gap-2.5 h-8 px-2.5 rounded-lg text-[13px] font-medium no-underline hover:no-underline transition-colors",
    isActive ? "bg-surface text-fg shadow-card border border-line" : "text-fg-2 hover:bg-surface-3 hover:text-fg border border-transparent",
  );
}

function ThemeSwitch() {
  const { pref, choose } = useTheme();
  const options: { id: ThemePref; icon: ComponentType<{ size?: number }>; label: string }[] = [
    { id: "light", icon: Sun, label: "Light" },
    { id: "system", icon: Monitor, label: "Match system" },
    { id: "dark", icon: Moon, label: "Dark" },
  ];
  return (
    <div role="radiogroup" aria-label="Theme" className="inline-flex p-0.5 rounded-lg bg-surface-3 border border-line">
      {options.map(({ id, icon: Icon, label }) => (
        <button
          key={id}
          role="radio"
          aria-checked={pref === id}
          title={label}
          aria-label={label}
          onClick={() => choose(id)}
          className={cn(
            "h-6 w-7 inline-flex items-center justify-center rounded-md border-0",
            pref === id ? "bg-surface text-fg shadow-card" : "bg-transparent text-fg-muted hover:text-fg",
          )}
        >
          <Icon size={14} />
        </button>
      ))}
    </div>
  );
}

/** Clients in use, linking to the Assessments list filtered to each. */
function ClientNav() {
  const [clients, setClients] = useState<ClientSummary[]>([]);
  const location = useLocation();
  const [params] = useSearchParams();
  const active = location.pathname === "/" ? params.get("client") : null;
  useEffect(() => {
    api.listClients().then(setClients).catch(() => setClients([]));
  }, [location.pathname, location.search]);
  if (clients.length === 0) return null;
  return (
    <div className="mt-6">
      <div className="eyebrow px-2.5 mb-1.5">Clients</div>
      <div className="flex flex-col gap-0.5">
        {clients.map((c) => (
          <NavLink
            key={c.name}
            to={`/?client=${encodeURIComponent(c.name)}`}
            className={() => navClass({ isActive: active === c.name })}
          >
            <span className="w-4 h-4 rounded bg-surface-3 border border-line text-[10px] font-semibold text-fg-2 inline-flex items-center justify-center shrink-0">
              {c.name.slice(0, 1).toUpperCase()}
            </span>
            <span className="truncate flex-1">{c.name}</span>
            <span className="tab-num text-[11px] text-fg-faint">{c.assessments}</span>
          </NavLink>
        ))}
      </div>
    </div>
  );
}

function Sidebar() {
  return (
    <aside className="no-print hidden lg:block w-[244px] shrink-0 bg-sidebar border-r border-line">
      <div className="flex flex-col h-screen sticky top-0 px-3 py-4">
      <NavLink to="/" className="px-2.5 pt-1 pb-5 block" aria-label={`${brand.company} — assessments`}>
        <Logo variant="full" height={32} title={brand.company} />
        <div className="text-[12px] text-fg-muted mt-2 font-medium">Firewall Best Practice Assessment</div>
      </NavLink>
      <nav className="flex flex-col gap-0.5">
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink key={to} to={to} end={end} className={navClass}>
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="flex-1 overflow-y-auto min-h-0">
        <ClientNav />
      </div>
      <div className="pt-4 border-t border-line flex items-center justify-between gap-2 px-1">
        {brand.website
          ? <a href={brand.website.href} className="text-[12px] text-fg-muted hover:text-fg">{brand.website.label}</a>
          : <span />}
        <ThemeSwitch />
      </div>
      </div>
    </aside>
  );
}

function MobileBar() {
  return (
    <header className="no-print lg:hidden sticky top-0 z-30 bg-sidebar/95 backdrop-blur border-b border-line">
      <div className="flex items-center gap-3 px-4 h-14">
        <NavLink to="/" aria-label={`${brand.company} — assessments`}>
          <Logo variant="full" height={22} title={brand.company} />
        </NavLink>
        <nav className="ml-auto flex items-center gap-1">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              aria-label={label}
              title={label}
              className={({ isActive }) => cn(
                "h-8 w-8 inline-flex items-center justify-center rounded-lg",
                isActive ? "bg-surface text-fg border border-line" : "text-fg-muted hover:bg-surface-3",
              )}
            >
              <Icon size={16} />
            </NavLink>
          ))}
        </nav>
      </div>
    </header>
  );
}

function App() {
  return (
    <div className="app-shell min-h-screen lg:flex bg-bg">
      <Sidebar />
      <div className="flex-1 min-w-0">
        <MobileBar />
        <main className="app-main mx-auto w-full max-w-[1320px] px-4 sm:px-6 lg:px-10 py-6 lg:py-8">
          <Routes>
            <Route path="/" element={<HistoryPage />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/assessments/:id" element={<DashboardPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/compare" element={<ComparePage />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default App;
