/* Curated inline stroke icons (lucide-style, 24×24, currentColor).
 * Inlined so the console has zero icon-library dependency and stays self-contained. */
import React from 'react';

const I = (paths) => function Icon({ size = 18, className, style, strokeWidth = 1.8, ...rest }) {
  return (
    <svg
      width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round"
      className={className} style={style} aria-hidden="true" {...rest}
    >
      {paths}
    </svg>
  );
};

export const ShieldIcon = I(<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></>);
export const GridIcon = I(<><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>);
export const TargetIcon = I(<><circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="5" /><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" /></>);
export const CrosshairIcon = I(<><circle cx="12" cy="12" r="8" /><line x1="12" y1="2" x2="12" y2="5" /><line x1="12" y1="19" x2="12" y2="22" /><line x1="2" y1="12" x2="5" y2="12" /><line x1="19" y1="12" x2="22" y2="12" /></>);
export const PlayIcon = I(<path d="M7 4.5v15l12-7.5-12-7.5z" fill="currentColor" stroke="none" />);
export const BugIcon = I(<><path d="M8 6a4 4 0 0 1 8 0" /><rect x="6" y="8" width="12" height="10" rx="6" /><path d="M12 8v10M3 12h3M18 12h3M4 8l2 1M20 8l-2 1M4 17l2-1M20 17l-2-1" /></>);
export const PlusIcon = I(<><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></>);
export const CheckIcon = I(<path d="m5 12 5 5L20 7" strokeWidth="2.4" />);
export const XIcon = I(<><line x1="6" y1="6" x2="18" y2="18" /><line x1="18" y1="6" x2="6" y2="18" /></>);
export const CopyIcon = I(<><rect x="9" y="9" width="12" height="12" rx="2.5" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></>);
export const ChevronRightIcon = I(<path d="m9 6 6 6-6 6" />);
export const ChevronLeftIcon = I(<path d="m15 6-6 6 6 6" />);
export const AlertIcon = I(<><path d="M10.3 3.3 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.3a2 2 0 0 0-3.4 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12" y2="17" /></>);
export const StopIcon = I(<rect x="6" y="6" width="12" height="12" rx="2.5" fill="currentColor" stroke="none" />);
export const ActivityIcon = I(<path d="M3 12h4l2 7 4-16 2 9h6" />);
export const ClockIcon = I(<><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>);
export const ExternalIcon = I(<><path d="M15 3h6v6" /><path d="M10 14 21 3" /><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /></>);
export const SearchIcon = I(<><circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.7" y2="16.7" /></>);
export const MenuIcon = I(<><line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" /></>);
export const LockIcon = I(<><rect x="4" y="10" width="16" height="11" rx="2.5" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></>);
export const FileIcon = I(<><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" /><path d="M14 3v5h5" /><line x1="9" y1="13" x2="15" y2="13" /><line x1="9" y1="17" x2="13" y2="17" /></>);
export const ZapIcon = I(<path d="M13 2 4 14h7l-1 8 9-12h-7l1-8z" />);
export const ArrowRightIcon = I(<><line x1="4" y1="12" x2="20" y2="12" /><path d="m14 6 6 6-6 6" /></>);
export const RefreshIcon = I(<><path d="M21 12a9 9 0 1 1-2.6-6.4" /><path d="M21 3v5h-5" /></>);
export const DownloadIcon = I(<><path d="M12 3v12" /><path d="m7 11 5 5 5-5" /><path d="M5 21h14" /></>);
export const KeyIcon = I(<><circle cx="7.5" cy="15.5" r="4.5" /><path d="m10.7 12.3 8.3-8.3M15 6l3 3M18 3l3 3" /></>);
export const DotIcon = I(<circle cx="12" cy="12" r="4" fill="currentColor" stroke="none" />);
export const GlobeIcon = I(<><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18z" /></>);
export const ServerIcon = I(<><rect x="3" y="4" width="18" height="7" rx="2" /><rect x="3" y="13" width="18" height="7" rx="2" /><line x1="7" y1="7.5" x2="7.02" y2="7.5" /><line x1="7" y1="16.5" x2="7.02" y2="16.5" /></>);
export const GitIcon = I(<><circle cx="6" cy="6" r="2.5" /><circle cx="6" cy="18" r="2.5" /><circle cx="18" cy="9" r="2.5" /><path d="M18 11.5v.5a4 4 0 0 1-4 4H6M6 8.5v7" /></>);
export const HandoffIcon = I(<><path d="M4 12h13" /><path d="m12 7 5 5-5 5" /><path d="M20 5v14" /></>);
export const SparkIcon = I(<path d="M12 3v4M12 17v4M3 12h4M17 12h4M6.3 6.3l2.4 2.4M15.3 15.3l2.4 2.4M17.7 6.3l-2.4 2.4M8.7 15.3l-2.4 2.4" />);
export const CircleCheckIcon = I(<><circle cx="12" cy="12" r="9" /><path d="m8.5 12 2.5 2.5 4.5-5" strokeWidth="2.1" /></>);
export const CircleXIcon = I(<><circle cx="12" cy="12" r="9" /><path d="m9 9 6 6M15 9l-6 6" strokeWidth="2.1" /></>);
export const InfoIcon = I(<><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></>);
