import React from 'react'
import { Sidebar } from './sidebar'
import { Topbar } from './Tobar'
type Children = {
    children: React.ReactNode
}

export const DashboardLayout: React.FC<Children> = ({ children }) => {
    return (
        <div className='overflow-x-hidden'>
            <Sidebar />

            <main className="relative min-h-screen w-[calc(100vw-240px)] p-8 left-60  bg-gray-50 ">
                <Topbar />
                <section>

                    {children}

                </section>

            </main>
        </div>
    )
}
