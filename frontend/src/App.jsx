import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Navbar from './components/Layout/Navbar'
import Sidebar from './components/Layout/Sidebar'
import Dashboard from './components/Dashboard/Dashboard'
import FileUpload from './components/FileUpload/FileUpload'
import AnalysisReport from './components/AnalysisReport/AnalysisReport'
import AnalysisList from './components/AnalysisReport/AnalysisList'
import YARAGenerator from './components/YARAGenerator/YARAGenerator'
import BehaviorGraph from './components/BehaviorGraph/BehaviorGraph'

function App() {
    return (
        <BrowserRouter>
            <div className="app">
                <Navbar />
                <div className="app-container">
                    <Sidebar />
                    <main className="main-content">
                        <Routes>
                            <Route path="/" element={<Dashboard />} />
                            <Route path="/upload" element={<FileUpload />} />
                            <Route path="/analyses" element={<AnalysisList />} />
                            <Route path="/analysis/:taskId" element={<AnalysisReport />} />
                            <Route path="/analysis/:taskId/graph" element={<BehaviorGraph />} />
                            <Route path="/yara" element={<YARAGenerator />} />
                        </Routes>
                    </main>
                </div>
            </div>
        </BrowserRouter>
    )
}

export default App
