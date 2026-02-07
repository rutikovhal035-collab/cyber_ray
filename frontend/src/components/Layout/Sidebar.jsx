import { NavLink } from 'react-router-dom'
import {
    LayoutDashboard,
    Upload,
    FileSearch,
    GitBranch,
    FileCode,
    Activity,
    FileText
} from 'lucide-react'

function Sidebar() {
    const navItems = [
        { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
        { path: '/upload', icon: Upload, label: 'Upload Sample' },
        { path: '/analyses', icon: FileSearch, label: 'Analyses' },
        { path: '/yara', icon: FileCode, label: 'YARA Rules' },
    ]

    return (
        <aside className="sidebar">
            <nav className="sidebar-nav">
                {navItems.map((item) => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                    >
                        <item.icon size={20} />
                        <span>{item.label}</span>
                    </NavLink>
                ))}
            </nav>

            <div style={{
                marginTop: '2rem',
                padding: '1rem',
                background: 'var(--gradient-card)',
                borderRadius: 'var(--radius-lg)',
                border: '1px solid var(--color-border)'
            }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <Activity size={16} style={{ color: 'var(--color-success)' }} />
                    <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>System Status</span>
                </div>
                <p style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>
                    All services operational
                </p>
            </div>

            <div style={{
                position: 'absolute',
                bottom: '1rem',
                left: '1rem',
                right: '1rem',
                fontSize: '0.75rem',
                color: 'var(--color-text-muted)',
                textAlign: 'center'
            }}>
                <FileText size={14} style={{ marginRight: '0.5rem' }} />
                CyberAy v1.0.0
            </div>
        </aside>
    )
}

export default Sidebar
