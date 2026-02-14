import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Shield, Bell, Settings, User } from 'lucide-react'

function Navbar() {
    const [showNotifications, setShowNotifications] = useState(false)
    const [showProfile, setShowProfile] = useState(false)

    return (
        <nav className="navbar">
            <Link to="/" className="navbar-brand">
                <Shield size={32} />
                <span>CyberAy Sandbox</span>
            </Link>

            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '1rem', position: 'relative' }}>
                <div style={{ position: 'relative' }}>
                    <button 
                        className={`btn btn-icon ${showNotifications ? 'active' : ''}`} 
                        title="Notifications"
                        onClick={() => {
                            setShowNotifications(!showNotifications)
                            setShowProfile(false)
                        }}
                    >
                        <Bell size={20} />
                        <span className="notification-badge">3</span>
                    </button>
                    
                    {showNotifications && (
                        <div className="dropdown-menu animate-fade-in">
                            <div className="dropdown-header">Notifications</div>
                            <div className="dropdown-item">
                                <p>New analysis completed: suspicious.exe</p>
                                <small>2 minutes ago</small>
                            </div>
                            <div className="dropdown-item">
                                <p>CAPE sandbox connected</p>
                                <small>10 minutes ago</small>
                            </div>
                            <div className="dropdown-item">
                                <p>Threat detected in invoice.pdf</p>
                                <small>1 hour ago</small>
                            </div>
                        </div>
                    )}
                </div>

                <button className="btn btn-icon" title="Settings">
                    <Settings size={20} />
                </button>

                <div style={{ position: 'relative' }}>
                    <button 
                        className={`btn btn-icon ${showProfile ? 'active' : ''}`} 
                        title="Profile"
                        onClick={() => {
                            setShowProfile(!showProfile)
                            setShowNotifications(false)
                        }}
                    >
                        <User size={20} />
                    </button>

                    {showProfile && (
                        <div className="dropdown-menu animate-fade-in" style={{ right: 0 }}>
                            <div className="dropdown-header">User Profile</div>
                            <div className="dropdown-item">Profile Settings</div>
                            <div className="dropdown-item">API Keys</div>
                            <div className="dropdown-divider"></div>
                            <div className="dropdown-item text-danger">Logout</div>
                        </div>
                    )}
                </div>
            </div>
        </nav>
    )
}

export default Navbar
