import { Link } from 'react-router-dom'
import { Shield, Bell, Settings, User } from 'lucide-react'

function Navbar() {
    return (
        <nav className="navbar">
            <Link to="/" className="navbar-brand">
                <Shield size={32} />
                <span>CyberAy Sandbox</span>
            </Link>

            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <button className="btn btn-icon" title="Notifications">
                    <Bell size={20} />
                </button>
                <button className="btn btn-icon" title="Settings">
                    <Settings size={20} />
                </button>
                <button className="btn btn-icon" title="Profile">
                    <User size={20} />
                </button>
            </div>
        </nav>
    )
}

export default Navbar
