import React, { useEffect, useState } from 'react';
import {
  Search,
  Menu,
  X,
  ShieldAlert,
  Compass,
  Gauge,
  LifeBuoy,
  Users,
  Scale,
  FlaskConical,
} from 'lucide-react';

export interface NavItem {
  id: string;
  label: string;
  shortLabel: string;
  fileTab: string;
  icon: React.ComponentType<{ className?: string }>;
}

export const NAV_ITEMS: NavItem[] = [
  { id: 'home', label: 'Home (Investigation Desk)', shortLabel: 'Home', fileTab: 'File 01', icon: Search },
  { id: 'guide', label: 'Forensic Guide', shortLabel: 'Forensic Guide', fileTab: 'File 02', icon: Compass },
  { id: 'index', label: 'Suspicion Index', shortLabel: 'Suspicion Index', fileTab: 'File 03', icon: Gauge },
  { id: 'actions', label: 'What To Do', shortLabel: 'What To Do', fileTab: 'File 04', icon: LifeBuoy },
  { id: 'witness', label: 'Witness Intel', shortLabel: 'Witness Intel', fileTab: 'File 05', icon: Users },
  { id: 'safety', label: 'Safety & Ethics', shortLabel: 'Safety & Ethics', fileTab: 'File 06', icon: Scale },
  { id: 'proof', label: 'Proof', shortLabel: 'Proof', fileTab: 'File 07', icon: FlaskConical },
];

interface NavbarProps {
  activeSection: string;
  onNavigate: (sectionId: string) => void;
  onInvestigateClick: () => void;
  isLightTheme?: boolean;
  onToggleTheme?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeSection,
  onNavigate,
  onInvestigateClick,
}) => {
  const [drawerOpen, setDrawerOpen] = useState(false);

  // Lock body scroll and listen for Escape key when drawer is open
  useEffect(() => {
    if (drawerOpen) {
      document.body.style.overflow = 'hidden';
      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') {
          setDrawerOpen(false);
        }
      };
      document.addEventListener('keydown', handleKeyDown);
      return () => {
        document.body.style.overflow = '';
        document.removeEventListener('keydown', handleKeyDown);
      };
    } else {
      document.body.style.overflow = '';
    }
  }, [drawerOpen]);

  const forensicOptions = NAV_ITEMS.filter((item) => item.id !== 'home');

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[100] focus:px-4 focus:py-2.5 focus:rounded brass-button font-semibold"
      >
        Skip to main content
      </a>

      <header
        className="sticky top-0 z-50 bg-[#170E0B]/95 backdrop-blur-md border-b border-[#4A3024] text-[#F2E6C9] shadow-lg"
        style={{ paddingTop: 'env(safe-area-inset-top)' }}
      >
        {/* Main Bar: Clean 3-element layout across all screen sizes */}
        <div className="max-w-[1440px] mx-auto px-3 sm:px-6 h-14 sm:h-16 flex items-center justify-between gap-2 sm:gap-4">
          {/* Left: Brand Logo & Title (Always returns to Home) */}
          <a
            href="#home"
            onClick={(e) => {
              e.preventDefault();
              onNavigate('home');
            }}
            className="flex items-center gap-2 sm:gap-2.5 shrink-0 group py-1 rounded focus-visible:outline-hidden"
            aria-label="SHERLOCK — The AI Digital Detective, return to Home"
          >
            <span className="w-9 h-9 sm:w-10 sm:h-10 rounded-full bg-[#2A1A14] border border-[#C9A04A] flex items-center justify-center shadow-inner group-hover:border-[#F5CE7A] transition-colors shrink-0">
              <Search className="w-4 h-4 sm:w-5 sm:h-5 text-[#C9A04A] group-hover:text-[#F5CE7A] transition-colors" />
            </span>
            <div className="flex flex-col leading-none">
              <span className="font-serif-display text-lg sm:text-2xl font-bold tracking-wider text-[#F2E6C9] group-hover:text-[#F5CE7A] transition-colors">
                SHERLOCK
              </span>
              <span className="text-[9px] sm:text-[11px] tracking-[0.12em] sm:tracking-[0.14em] uppercase text-[#D9C79F]">
                AI Digital Detective
              </span>
            </div>
          </a>

          {/* Right Controls: "Investigate a link" Button + Three-Line Hamburger Menu Toggle */}
          <div className="flex items-center gap-1.5 sm:gap-3 shrink-0">
            <button
              type="button"
              onClick={onInvestigateClick}
              className="min-h-[44px] inline-flex items-center gap-1.5 px-3 sm:px-4 py-2 rounded text-xs sm:text-sm font-semibold brass-button whitespace-nowrap shrink-0 cursor-pointer shadow-sm"
            >
              <Search className="w-3.5 h-3.5 shrink-0" />
              <span>
                Investigate<span className="hidden sm:inline"> a link</span>
              </span>
            </button>

            {/* Three-Line (Hamburger) Menu Button - Visible on all screen sizes */}
            <button
              type="button"
              onClick={() => setDrawerOpen(true)}
              aria-label="Open forensic study options menu"
              aria-expanded={drawerOpen}
              className="min-w-[44px] min-h-[44px] px-2.5 py-1.5 rounded-md border border-[#C9A04A]/80 bg-[#2A1A14] hover:bg-[#38231C] hover:border-[#F5CE7A] text-[#F2E6C9] flex items-center justify-center gap-2 cursor-pointer transition shadow-sm group"
            >
              <Menu className="w-5 h-5 text-[#C9A04A] group-hover:text-[#F5CE7A] transition-colors" />
              <span className="hidden sm:inline font-mono-code text-xs uppercase tracking-wider text-[#F5CE7A] font-semibold">
                Menu
              </span>
            </button>
          </div>
        </div>
      </header>

      {/* Slide-Out Side Drawer (Responsive across all screens) */}
      {drawerOpen && (
        <div
          className="fixed inset-0 z-[90] flex justify-end bg-black/75 backdrop-blur-xs transition-opacity animate-in fade-in duration-200"
          role="dialog"
          aria-modal="true"
          aria-label="Forensic navigation menu"
          onClick={(e) => {
            if (e.target === e.currentTarget) setDrawerOpen(false);
          }}
        >
          <div
            className="w-full max-w-sm sm:max-w-md bg-[#170E0B] border-l-2 border-[#C9A04A]/70 h-full flex flex-col justify-between overflow-y-auto text-[#F2E6C9] shadow-2xl animate-in slide-in-from-right duration-250"
            style={{
              paddingTop: 'env(safe-area-inset-top)',
              paddingBottom: 'env(safe-area-inset-bottom)',
            }}
          >
            <div>
              {/* Drawer Header */}
              <div className="px-5 py-4 border-b border-[#4A3024] flex items-center justify-between bg-[#2A1A14]">
                <div className="flex items-center gap-2.5">
                  <span className="w-8 h-8 rounded-full bg-[#170E0B] border border-[#C9A04A] flex items-center justify-center">
                    <ShieldAlert className="w-4 h-4 text-[#C9A04A]" />
                  </span>
                  <div>
                    <p className="font-serif-display text-lg font-bold text-[#F5CE7A] leading-tight">
                      SHERLOCK Study Index
                    </p>
                    <p className="text-xs text-[#D9C79F]">Forensic Guide &amp; Case Files</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setDrawerOpen(false)}
                  aria-label="Close navigation drawer"
                  className="min-w-[44px] min-h-[44px] rounded border border-[#4A3024] bg-[#170E0B] text-[#F2E6C9] flex items-center justify-center hover:border-[#C9A04A] hover:text-[#F5CE7A] cursor-pointer transition"
                >
                  <X className="w-5 h-5 text-[#C9A04A]" />
                </button>
              </div>

              {/* Drawer Content */}
              <div className="p-4 space-y-4">
                {/* Home Desk quick return option */}
                <a
                  href="#home"
                  onClick={(e) => {
                    e.preventDefault();
                    setDrawerOpen(false);
                    onNavigate('home');
                  }}
                  className={`min-h-[48px] px-3.5 py-3 rounded border flex items-center justify-between transition-colors ${
                    activeSection === 'home'
                      ? 'bg-[#5A1F26] border-[#C9A04A] text-[#F5CE7A] font-semibold shadow-md'
                      : 'bg-[#22140F] border-[#4A3024] text-[#F2E6C9] hover:border-[#C9A04A]/60 hover:bg-[#2A1A14]'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Search className="w-4 h-4 text-[#C9A04A] shrink-0" />
                    <div>
                      <div className="text-sm font-bold">Home Page</div>
                      <div className="text-[11px] text-[#D9C79F]">URL Investigation Desk &amp; Live Risk Meter</div>
                    </div>
                  </div>
                  <span className="font-mono-code text-xs text-[#F5CE7A] bg-[#170E0B] px-1.5 py-0.5 rounded border border-[#4A3024]">
                    File 01
                  </span>
                </a>

                <div className="pt-2 border-t border-[#4A3024]/80">
                  <div className="px-1 pb-2 flex items-center justify-between">
                    <span className="font-mono-code text-xs uppercase tracking-wider text-[#F5CE7A] font-semibold">
                      Study Sections
                    </span>
                    <span className="text-[11px] text-[#8C7464] font-mono-code">6 Options</span>
                  </div>

                  {/* The 6 Forensic Options specified by user */}
                  <nav aria-label="Forensic Sections Navigation" className="space-y-2">
                    {forensicOptions.map((item) => {
                      const Icon = item.icon;
                      const isActive = activeSection === item.id;
                      return (
                        <a
                          key={item.id}
                          href={`#${item.id}`}
                          onClick={(e) => {
                            e.preventDefault();
                            setDrawerOpen(false);
                            onNavigate(item.id);
                          }}
                          aria-current={isActive ? 'page' : undefined}
                          className={`min-h-[48px] px-3.5 py-2.5 rounded border flex items-center justify-between transition-all ${
                            isActive
                              ? 'bg-[#5A1F26] border-[#C9A04A] text-[#F5CE7A] font-semibold shadow-md border-l-4'
                              : 'bg-[#2A1A14]/90 border-[#4A3024] text-[#F2E6C9] hover:border-[#C9A04A]/60 hover:bg-[#362119]'
                          }`}
                        >
                          <div className="flex items-center gap-3">
                            <span
                              className={`w-8 h-8 rounded flex items-center justify-center shrink-0 ${
                                isActive ? 'bg-[#170E0B] text-[#F5CE7A]' : 'bg-[#1F130E] text-[#C9A04A]'
                              }`}
                            >
                              <Icon className="w-4 h-4" />
                            </span>
                            <span className="text-sm font-medium">{item.shortLabel}</span>
                          </div>
                          <span className="font-mono-code text-xs text-[#D9C79F]">{item.fileTab}</span>
                        </a>
                      );
                    })}
                  </nav>
                </div>
              </div>
            </div>

            {/* Bottom Actions in Drawer */}
            <div className="p-4 border-t border-[#4A3024] bg-[#2A1A14] space-y-2">
              <button
                type="button"
                onClick={() => {
                  setDrawerOpen(false);
                  onInvestigateClick();
                }}
                className="w-full min-h-[48px] rounded brass-button font-bold text-sm flex items-center justify-center gap-2 cursor-pointer shadow-md"
              >
                <Search className="w-4 h-4" />
                <span>Investigate a link on Home Desk</span>
              </button>
              <p className="text-[11px] text-center text-[#8C7464] font-mono-code">
                Defensive use only · Public telemetry only
              </p>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
